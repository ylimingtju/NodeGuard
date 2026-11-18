import Darwin
import Foundation
import Security

struct IPv4Root: Hashable {
    let pid: pid_t
    let seconds: UInt64
    let microseconds: UInt64
}

enum IPv4Entry {
    private static let corePath = "/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo"
    private static let bridgePath = "/Applications/ProxyBridge.app/Contents/MacOS/ProxyBridge"

    // Gatekeeper may run a signed app at …/AppTranslocation/<UUID>/d/<app>.
    static func installedExecutable(for path: String, among expected: Set<String>) -> String? {
        if expected.contains(path) { return path }
        guard let marker = path.range(of: "/AppTranslocation/", options: .backwards) else { return nil }
        let parts = path[marker.upperBound...].split(separator: "/", maxSplits: 2)
        guard parts.count == 3, UUID(uuidString: String(parts[0])) != nil, parts[1] == "d",
              let bundleName = parts[2].split(separator: "/").first, bundleName.hasSuffix(".app"),
              let installed = expected.first(where: { $0.hasSuffix("/" + parts[2]) }) else { return nil }
        let suffix = "/Contents/MacOS/"
        guard let originalEnd = installed.range(of: suffix, options: .backwards),
              let actualEnd = path.range(of: suffix, options: .backwards) else { return nil }
        let originalURL = URL(fileURLWithPath: String(installed[..<originalEnd.lowerBound]))
        let actualURL = URL(fileURLWithPath: String(path[..<actualEnd.lowerBound]))
        var original: SecStaticCode?, actual: SecStaticCode?, requirement: SecRequirement?
        guard SecStaticCodeCreateWithPath(originalURL as CFURL, [], &original) == errSecSuccess, let original,
              SecCodeCopyDesignatedRequirement(original, [], &requirement) == errSecSuccess, let requirement,
              SecStaticCodeCreateWithPath(actualURL as CFURL, [], &actual) == errSecSuccess, let actual,
              SecStaticCodeCheckValidity(actual, SecCSFlags(rawValue: kSecCSDoNotValidateResources),
                                         requirement) == errSecSuccess else { return nil }
        return installed
    }

    // Check the actual executable paths, including while Launch Services is still registering the app.
    static func verifiedRoots() -> Set<IPv4Root> {
        guard let pids = AgentCloser.userPIDs() else { return [] }
        let launcherDir = NSHomeDirectory() + "/Applications/"
        let entries = [("Antigravity", "com.google.antigravity"), ("Gemini", "com.google.GeminiMacOS")]
        var byPath: [String: [pid_t]] = [:]
        var paths: Set<String> = [corePath, bridgePath]
        for (name, _) in entries {
            paths.insert(launcherDir + name + " IPv4.app/Contents/MacOS/Launcher")
            paths.insert("/Applications/\(name).app/Contents/MacOS/\(name)")
        }
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        for pid in pids where pid > 1 {
            let capacity = UInt32(buffer.count)
            guard proc_pidpath(pid, &buffer, capacity) > 0 else { continue }
            let path = String(cString: buffer)
            if let installed = installedExecutable(for: path, among: paths) {
                byPath[installed, default: []].append(pid)
            }
        }
        guard let cores = byPath[corePath] else { return [] }
        var verified = Set<IPv4Root>()
        for (name, bundleID) in entries {
            let mainBundle = "/Applications/\(name).app"
            let launcherBundle = launcherDir + name + " IPv4.app"
            guard let mains = byPath[mainBundle + "/Contents/MacOS/" + name],
                  let launchers = byPath[launcherBundle + "/Contents/MacOS/Launcher"],
                  Bundle(path: mainBundle)?.bundleIdentifier == bundleID,
                  Bundle(path: launcherBundle)?.bundleIdentifier == "local.\(name.lowercased()).ipv4-launcher" else { continue }
            if name == "Gemini" {
                guard let bridges = byPath[bridgePath] else { continue }
                for launcher in launchers {
                    verified.formUnion(geminiRoots(launcher: launcher, mains: mains, bridges: bridges, cores: cores))
                }
                continue
            }
            for core in cores {
                guard let info = AgentCloser.processInfo(core), launchers.contains(pid_t(info.pbi_ppid)),
                      let port = configuredPort(core), listens(core, on: port) else { continue }
                let endpoint = "http://127.0.0.1:\(port)"
                for main in mains {
                    guard let root = identity(main), let args = launchArguments(main) else { continue }
                    let servers = args.filter { $0.hasPrefix("--proxy-server=") }
                    if args.contains("--disable-quic"), servers == ["--proxy-server=" + endpoint],
                       identity(main) == root { verified.insert(root) }
                }
            }
        }
        return verified
    }

    // sandbox-exec replaces itself with Gemini. The bridge and core are its siblings.
    static func geminiRoots(launcher: pid_t, mains: [pid_t], bridges: [pid_t], cores: [pid_t]) -> Set<IPv4Root> {
        guard let owner = identity(launcher),
              let bridge = bridges.lazy.compactMap({ identity($0, parent: launcher) }).first,
              let core = cores.lazy.compactMap({ identity($0, parent: launcher) }).first(where: { listens($0.pid) })
        else { return [] }
        let roots = Set(mains.compactMap { identity($0, parent: launcher) })
        guard identity(bridge.pid, parent: launcher) == bridge, identity(core.pid, parent: launcher) == core,
              identity(launcher) == owner else { return [] }
        return roots
    }

    private static func identity(_ pid: pid_t, parent: pid_t? = nil) -> IPv4Root? {
        guard let info = AgentCloser.processInfo(pid), info.pbi_uid == getuid(), info.pbi_status != SZOMB,
              parent == nil || parent == pid_t(info.pbi_ppid) else { return nil }
        return IPv4Root(pid: pid, seconds: info.pbi_start_tvsec, microseconds: info.pbi_start_tvusec)
    }

    // KERN_PROCARGS2 contains argc, the executable, padding, then NUL-delimited argv and environment.
    private static func launchArguments(_ pid: pid_t) -> [String]? {
        var mib = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return nil }
        var data = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &data, &size, nil, 0) == 0,
              size > MemoryLayout<Int32>.size, size <= data.count else { return nil }
        let argc = Int(data.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) })
        let bytes = data[MemoryLayout<Int32>.size..<size]
        guard argc > 0, let executableEnd = bytes.firstIndex(of: 0),
              let firstArgument = bytes[executableEnd...].firstIndex(where: { $0 != 0 }) else { return nil }
        let fields = bytes[firstArgument...].split(separator: 0, omittingEmptySubsequences: false)
        guard fields.count >= argc else { return nil }
        return fields.prefix(argc).map { String(decoding: $0, as: UTF8.self) }
    }

    private static func configuredPort(_ core: pid_t) -> UInt16? {
        guard let args = launchArguments(core), let i = args.firstIndex(of: "-config"), i + 1 < args.count,
              let data = Data(base64Encoded: args[i + 1]),
              let config = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              config["ipv6"] as? Bool == false, config["mode"] as? String == "rule",
              config["rules"] as? [String] == ["MATCH,IPv4"],
              let proxies = config["proxies"] as? [[String: Any]], proxies.count == 1,
              proxies[0]["name"] as? String == "IPv4", proxies[0]["type"] as? String == "direct",
              proxies[0]["ip-version"] as? String == "ipv4", let port = config["port"] as? Int,
              port > 0 else { return nil }
        return UInt16(exactly: port)
    }

    private static func listens(_ pid: pid_t, on port: UInt16? = nil) -> Bool {
        let stride = MemoryLayout<proc_fdinfo>.stride
        let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard bytes > 0 else { return false }
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(bytes) / stride + 16)
        let capacity = Int32(fds.count * stride)
        let count = Int(proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, capacity)) / stride
        let size = Int32(MemoryLayout<socket_fdinfo>.size)
        for fd in fds.prefix(max(0, count)) where fd.proc_fdtype == PROX_FDTYPE_SOCKET {
            var socket = socket_fdinfo()
            guard proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &socket, size) == size,
                  socket.psi.soi_family == AF_INET, socket.psi.soi_protocol == IPPROTO_TCP else { continue }
            let tcp = socket.psi.soi_proto.pri_tcp
            if let port, tcp.tcpsi_ini.insi_lport != Int32(port.bigEndian) { continue }
            if tcp.tcpsi_state == TSI_S_LISTEN &&
                tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr == INADDR_LOOPBACK.bigEndian { return true }
        }
        return false
    }
}
