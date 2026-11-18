import AppKit
import Darwin

struct CloseReport {
    let closed: [String]
    let failed: [String]
}

enum AgentCloser {
    private enum Agent: String {
        case antigravity = "com.google.antigravity"
        case gemini = "com.google.GeminiMacOS"
        case codex = "com.openai.codex"
        case claude = "com.anthropic.claudefordesktop"

        var title: String {
            switch self {
            case .antigravity: return "Antigravity"
            case .gemini: return "Gemini"
            case .codex: return "ChatGPT"
            case .claude: return "Claude"
            }
        }
    }

    static var googleIPv4Entries: [(id: String, title: String)] {
        [Agent.antigravity, .gemini].map { ($0.rawValue, $0.title) }
    }

    private struct ProcessRef {
        let agent: Agent
        let pid: pid_t
        let path: String
        let seconds: UInt64
        let microseconds: UInt64

        var identity: IPv4Root { IPv4Root(pid: pid, seconds: seconds, microseconds: microseconds) }

        func stillRunning() -> Bool {
            guard let info = AgentCloser.processInfo(pid) else { return errno != ESRCH && errno != ENOENT }
            return info.pbi_status != SZOMB && info.pbi_start_tvsec == seconds
                && info.pbi_start_tvusec == microseconds
        }

        @MainActor func forceQuit() {
            if var token = AgentCloser.auditToken(pid), stillRunning() {
                var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
                let size = UInt32(buffer.count)
                if proc_pidpath_audittoken(&token, &buffer, size) > 0,
                   String(cString: buffer) == path,
                   proc_signal_with_audittoken(&token, SIGKILL) == 0 { return }
            }
            // Some signed applications restrict access to their Mach task port.
            guard let app = NSRunningApplication(processIdentifier: pid),
                  let id = app.bundleIdentifier, id == agent.rawValue || id.hasPrefix(agent.rawValue + "."),
                  app.executableURL?.path == path,
                  let info = AgentCloser.processInfo(pid), info.pbi_start_tvsec == seconds,
                  info.pbi_start_tvusec == microseconds else { return }
            app.forceTerminate()
        }
    }

    private static func auditToken(_ pid: pid_t) -> audit_token_t? {
        var port = mach_port_name_t()
        guard task_name_for_pid(mach_task_self_, pid, &port) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, port) }
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let capacity = Int(count)
        let result = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: capacity) {
                task_info(port, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? token : nil
    }

    static func processInfo(_ pid: pid_t) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout.size(ofValue: info))
        return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size ? info : nil
    }

    private struct Registry {
        let targets: [Agent]
        var roots: [String: Agent] = [:]
        var registered: [pid_t: Agent] = [:]
        var mains: [pid_t: Agent] = [:]
        var executables: [pid_t: String] = [:]
    }

    private static func appRoot(_ executable: String) -> String? {
        guard let range = executable.range(of: ".app/Contents/") else { return nil }
        return String(executable[..<range.lowerBound]) + ".app"
    }

    @MainActor private static func registry(for targets: [Agent]) -> Registry {
        var result = Registry(targets: targets)
        for app in NSWorkspace.shared.runningApplications {
            guard let id = app.bundleIdentifier, let path = app.executableURL?.path,
                  let root = appRoot(path) else { continue }
            let isHelper = path.hasPrefix(root + "/Contents/Helpers/")
                || path.hasPrefix(root + "/Contents/Frameworks/")
            guard let agent = targets.first(where: {
                id == $0.rawValue || (isHelper && id.hasPrefix($0.rawValue + "."))
            }) else { continue }
            result.roots[root] = agent
            result.registered[app.processIdentifier] = agent
            result.executables[app.processIdentifier] = path
            if id == agent.rawValue { result.mains[app.processIdentifier] = agent }
        }
        return result
    }

    static func userPIDs() -> [pid_t]? {
        let stride = MemoryLayout<pid_t>.stride
        let size = proc_listpids(UInt32(PROC_UID_ONLY), getuid(), nil, 0)
        guard size > 0 else { return nil }
        var capacity = Int(size) / stride + 32
        while true {
            var pids = [pid_t](repeating: 0, count: capacity)
            let bytes = Int32(capacity * stride)
            let used = proc_listpids(UInt32(PROC_UID_ONLY), getuid(), &pids, bytes)
            guard used > 0 else { return nil }
            if used < bytes { return Array(pids.prefix(Int(used) / stride)) }
            capacity *= 2
        }
    }

    static func ipv4EntryStatuses() async -> [String: String] {
        let apps = await registry(for: [.antigravity, .gemini])
        guard !apps.mains.isEmpty else { return [:] }
        let verified = IPv4Entry.verifiedRoots()
        var states: [String: Set<String>] = [:]
        for (pid, agent) in apps.mains {
            guard let info = processInfo(pid), info.pbi_status != SZOMB else { continue }
            let id = IPv4Root(pid: pid, seconds: info.pbi_start_tvsec, microseconds: info.pbi_start_tvusec)
            states[agent.rawValue, default: []].insert(verified.contains(id) ? "IPv4 专用入口" : "普通入口")
        }
        return states.mapValues { $0.count > 1 ? "普通及 IPv4 入口" : $0.first! }
    }

    private struct Scan {
        var targets: [ProcessRef] = []
        var skipped = Set<IPv4Root>()
        var ordinaryDescendants = Set<IPv4Root>()
        var unresolved = Set<Agent>()
    }

    private static func snapshot(_ registry: Registry, allowing exemptIDs: Set<String>,
                                 knownOrdinary: Set<IPv4Root>) -> Scan {
        let userProcesses = userPIDs()
        let pids = userProcesses ?? Array(registry.registered.keys)
        var roots = registry.roots
        var otherRoots = Set<String>()
        var parents: [pid_t: pid_t] = [:]
        var owners: [pid_t: Agent] = [:]
        var mains: [pid_t: IPv4Root] = [:]
        var uninspected: [pid_t: Agent] = [:]
        var candidates: [ProcessRef] = []
        let support = NSHomeDirectory() + "/Library/Application Support/"
        let pathSize = Int(MAXPATHLEN) * 4
        var buffer = [CChar](repeating: 0, count: pathSize)
        for pid in pids where pid > 1 && pid != getpid() {
            guard let info = processInfo(pid) else {
                if errno != ESRCH && errno != ENOENT { uninspected[pid] = registry.registered[pid] }
                continue
            }
            guard info.pbi_status != SZOMB, info.pbi_uid == getuid() else { continue }
            parents[pid] = pid_t(info.pbi_ppid)
            let path: String
            if proc_pidpath(pid, &buffer, UInt32(pathSize)) > 0 {
                path = String(cString: buffer)
            } else if let registeredPath = registry.executables[pid] {
                path = registeredPath
            } else { continue }
            var agent: Agent?
            if let root = appRoot(path) {
                if roots[root] == nil && !otherRoots.contains(root) {
                    if let id = Bundle(path: root)?.bundleIdentifier, let found = Agent(rawValue: id),
                       registry.targets.contains(found) {
                        roots[root] = found
                    } else {
                        otherRoots.insert(root)
                    }
                }
                agent = roots[root]
                let isMain = agent != nil && (registry.mains[pid] == agent || path == Bundle(path: root)?.executableURL?.path)
                if isMain {
                    mains[pid] = IPv4Root(pid: pid, seconds: info.pbi_start_tvsec, microseconds: info.pbi_start_tvusec)
                }
                if let agent, registry.registered[pid] == agent
                    || path.hasPrefix(root + "/Contents/Helpers/")
                    || path.hasPrefix(root + "/Contents/Frameworks/")
                    || (agent == .antigravity && path == root + "/Contents/Resources/bin/language_server")
                    || isMain {
                    owners[pid] = agent
                }
            }
            if agent == nil && registry.targets.contains(.antigravity) && path.hasPrefix(support + "Antigravity/bin/") {
                agent = .antigravity
            }
            if agent == nil && registry.targets.contains(.claude) && path.hasPrefix(support + "Claude/claude-code/") {
                agent = .claude
            }
            guard let agent else { continue }
            candidates.append(ProcessRef(agent: agent, pid: pid, path: path,
                                         seconds: info.pbi_start_tvsec, microseconds: info.pbi_start_tvusec))
        }
        // Check the listener after enumerating candidates so new instances get their own proof.
        let verify = candidates.contains { exemptIDs.contains($0.agent.rawValue) } ||
            uninspected.values.contains { exemptIDs.contains($0.rawValue) }
        let verified = verify ? IPv4Entry.verifiedRoots() : []
        let protectedAgents = Set(verified.compactMap { root -> Agent? in
            let agent = mains[root.pid] == root ? owners[root.pid] :
                (uninspected[root.pid] != nil ? registry.mains[root.pid] : nil)
            guard let agent, exemptIDs.contains(agent.rawValue) else { return nil }
            return agent
        })
        var scan = Scan()
        for (pid, agent) in uninspected {
            if !protectedAgents.contains(agent) || (registry.mains[pid] != nil && !verified.contains(where: { $0.pid == pid })) {
                scan.unresolved.insert(agent)
            }
        }
        for candidate in candidates {
            var ancestor = candidate.pid
            var visited = Set<pid_t>()
            var owner: Agent?
            var main: IPv4Root?
            while ancestor > 1 && visited.insert(ancestor).inserted {
                owner = owner ?? owners[ancestor]
                if let found = mains[ancestor] {
                    if owners[ancestor] == candidate.agent { main = found }
                    break
                }
                ancestor = parents[ancestor] ?? 0
            }
            if protectedAgents.contains(candidate.agent) {
                // A reparented helper sharing a bundle with a protected instance is ambiguous,
                // unless we saw it under the ordinary instance before signalling that instance.
                let exempt = main.map(verified.contains) ?? !knownOrdinary.contains(candidate.identity)
                if exempt {
                    scan.skipped.insert(candidate.identity)
                    continue
                }
            }
            guard owner == candidate.agent else { continue }
            if main != nil { scan.ordinaryDescendants.insert(candidate.identity) }
            if userProcesses != nil { scan.targets.append(candidate) }
            else { scan.unresolved.insert(candidate.agent) }
        }
        return scan
    }

    static func closeRunning(for service: GuardService,
                             policy: @MainActor @Sendable () -> Set<String>?) async -> CloseReport {
        let targets: [Agent]
        switch service {
        case .google: targets = [.gemini, .antigravity]
        case .chatgpt: targets = [.codex]
        case .claude: targets = [.claude]
        }
        guard let exemptIDs = await policy() else { return CloseReport(closed: [], failed: []) }
        let apps = await registry(for: targets)
        var scan = snapshot(apps, allowing: exemptIDs, knownOrdinary: [])
        var ordinary = scan.ordinaryDescendants
        var observed: [IPv4Root: ProcessRef] = [:]
        var live = scan.targets
        // A helper can launch during the initial scan. Include it without waiting on each individual app.
        for _ in 0..<2 {
            guard !live.isEmpty else { break }
            let batch = live
            // The policy can change while the process table is being read. Apply the
            // decision and send signals in the same main-actor turn as the lock check.
            let sent = await MainActor.run {
                guard policy() == exemptIDs else { return false }
                for process in batch { process.forceQuit() }
                return true
            }
            guard sent else {
                let attempted = Set(observed.values.map(\.agent))
                let surviving = Set(observed.values.filter { $0.stillRunning() }.map(\.agent))
                return CloseReport(closed: targets.filter { attempted.contains($0) && !surviving.contains($0) }.map(\.title),
                                   failed: [])
            }
            for process in batch { observed[process.identity] = process }
            try? await Task.sleep(nanoseconds: 180_000_000)
            scan = snapshot(await registry(for: targets), allowing: exemptIDs, knownOrdinary: ordinary)
            ordinary.formUnion(scan.ordinaryDescendants)
            for id in scan.skipped { observed.removeValue(forKey: id) }
            var seen = Set(scan.targets.map(\.identity))
            live = scan.targets + observed.values.filter { seen.insert($0.identity).inserted && $0.stillRunning() }
        }
        let affected = Set(observed.values.map(\.agent))
        let remaining = Set(live.map(\.agent)).union(scan.unresolved)
        return CloseReport(closed: targets.filter { affected.contains($0) && !remaining.contains($0) }.map(\.title),
                           failed: targets.filter(remaining.contains).map(\.title))
    }
}
