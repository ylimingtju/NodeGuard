import AppKit
import SystemConfiguration

private final class ServiceState {
    var lock: ServiceLock?
    var lastEvent: GuardEvent?
    var enforcing = false
    var pending = false
    var announce = false
    var failures = Set<String>()
}

@MainActor
private final class GuardController: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private let defaults = UserDefaults.standard
    private let card = EventCard()
    private let menu = NSMenu()
    private var item: NSStatusItem!
    private var watching = false
    private var armed = false
    private var paths: [ProbePath] = []
    private var latest: [ProbePath: ProbeReading] = [:]
    private var previousKnown: [ProbePath: ProbeReading] = [:]
    private var lastChecked: Date?
    private var poll: Task<Void, Never>?
    private var round = 0
    private var timer: Timer?
    private var store: SCDynamicStore?
    private var applications: NSKeyValueObservation?
    private var entryStatuses: [String: String] = [:]
    private var entryRows: [String: NSMenuItem] = [:]
    private var readingEntries = false
    private let services = Dictionary(uniqueKeysWithValues: GuardService.allCases.map { ($0, ServiceState()) })
    private lazy var serviceMarks: [GuardService: NSImage] = {
        var marks: [GuardService: NSImage] = [:]
        for service in GuardService.allCases {
            if let url = Bundle.main.url(forResource: service.rawValue, withExtension: "svg") {
                marks[service] = NSImage(contentsOf: url)
            }
        }
        return marks
    }()

    func applicationDidFinishLaunching(_ notification: Notification) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.menu = menu
        menu.delegate = self
        item.button?.imagePosition = .imageLeading
        let preview = CommandLine.arguments.contains("--preview")
        let monitorOnly = CommandLine.arguments.contains("--monitor-only")
        for entry in AgentCloser.googleIPv4Entries {
            defaults.register(defaults: [whitelistKey(entry.id): true])
        }
        armed = !preview && !monitorOnly && defaults.bool(forKey: "armed")
        for (service, state) in services {
            state.lastEvent = load(GuardEvent.self, "lastEvent", service)
            if armed { state.lock = load(ServiceLock.self, "lock", service) }
        }
        if !preview || monitorOnly { startWatching() } else { updateStatus() }
        if preview { card.show(.sample, preview: true) }
        menuNeedsUpdate(menu)
    }

    private func load<T: Decodable>(_ type: T.Type, _ key: String, _ service: GuardService) -> T? {
        guard let data = defaults.data(forKey: "\(service.rawValue).\(key)") else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }

    private func save<T: Encodable>(_ value: T?, as key: String, for service: GuardService) {
        let key = "\(service.rawValue).\(key)"
        if let value, let data = try? JSONEncoder().encode(value) {
            defaults.set(data, forKey: key)
        } else {
            defaults.removeObject(forKey: key)
        }
    }

    private func startWatching() {
        guard !watching else { return }
        watching = true
        // Running applications includes background launchers that have no Dock icon.
        applications = NSWorkspace.shared.observe(\.runningApplications) { [weak self] _, _ in
            Task { @MainActor in self?.enforceLockedServices() }
        }
        NSWorkspace.shared.notificationCenter.addObserver(
            self, selector: #selector(networkChanged), name: NSWorkspace.didWakeNotification, object: nil
        )
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                            retain: nil, release: nil, copyDescription: nil)
        store = SCDynamicStoreCreate(nil, "NodeGuard" as CFString, { _, _, pointer in
            guard let pointer else { return }
            let controller = Unmanaged<GuardController>.fromOpaque(pointer).takeUnretainedValue()
            Task { @MainActor in controller.networkChanged() }
        }, &context)
        if let store {
            let patterns = ["State:/Network/Global/(IPv4|IPv6|Proxies|DNS)",
                            "State:/Network/(Interface|Service)/[^/]+/(Link|AirPort|IPv4|IPv6|Proxies)"]
            SCDynamicStoreSetNotificationKeys(store, nil, patterns as CFArray)
            SCDynamicStoreSetDispatchQueue(store, .main)
        }
        let timer = Timer(timeInterval: 5, target: self, selector: #selector(tick), userInfo: nil, repeats: true)
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
        tick()
    }

    @objc private func networkChanged() {
        poll?.cancel()
        poll = nil
        latest.removeAll()
        lastChecked = nil
        tick()
    }

    @objc private func tick() {
        enforceLockedServices()
        guard poll == nil else { return }
        round += 1
        let id = round
        poll = Task {
            let active = await Task.detached(priority: .utility) { EgressProbe.paths() }.value
            guard !Task.isCancelled, round == id else { return }
            paths = active
            latest = latest.filter { active.contains($0.key) }
            updateStatus()
            var safe = Set<ProbePath>()
            var pending = Set(active)
            await withTaskGroup(of: (ProbePath, ProbeReading?).self) { group in
                for path in active {
                    group.addTask { (path, await EgressProbe.read(path)) }
                }
                for await (path, reading) in group {
                    guard !Task.isCancelled, round == id else { continue }
                    latest[path] = reading
                    if let reading {
                        let previous = previousKnown.updateValue(reading, forKey: path)
                        if reading.country == "CN" {
                            if armed { detect(path, before: previous, now: reading) }
                        } else {
                            safe.insert(path)
                        }
                    }
                    pending.remove(path)
                    if path.service == .google, let state = services[.google], var lock = state.lock {
                        if lock.recoverGoogleFamily(path.family, active: active, safe: safe) {
                            if lock.affectedPaths.isEmpty { clearLock(for: .google) }
                            else {
                                state.lock = lock
                                save(lock, as: "lock", for: .google)
                                enforce(.google)
                            }
                        }
                    } else if !pending.contains(where: { $0.service == path.service }),
                       let lock = services[path.service]?.lock,
                       active.filter({ $0.service == path.service }).allSatisfy(safe.contains),
                       lock.affectedPaths.isSubset(of: safe) {
                        clearLock(for: path.service)
                    }
                    updateStatus()
                }
            }
            guard !Task.isCancelled, round == id else { return }
            lastChecked = Date()
            poll = nil
            updateStatus()
        }
    }

    private func detect(_ path: ProbePath, before: ProbeReading?, now: ProbeReading) {
        guard let state = services[path.service] else { return }
        let event = GuardEvent(path: path, previous: before, current: now, time: Date(), closed: [], failed: [])
        if var lock = state.lock {
            let newFamily = !lock.affectedPaths.contains(where: { $0.family == path.family })
            let inserted = lock.affectedPaths.insert(path).inserted
            if path.service == .google && lock.googleEvents == nil {
                lock.googleEvents = [lock.cause.path.family: lock.cause]
            }
            let old = lock.googleEvents?[path.family] ?? lock.cause
            let replaceCause = old.path == path || latest[old.path]?.country != "CN"
                || (path.service == .google && lock.googleEvents?[path.family] == nil)
            if replaceCause {
                lock.cause = event
                lock.googleEvents?[path.family] = event
            }
            state.lock = lock
            if inserted || (replaceCause && (old.path != path || old.current.ip != now.ip ||
                                             old.current.destinationIP != now.destinationIP)) {
                save(lock, as: "lock", for: path.service)
            }
            if path.service == .google && newFamily {
                enforce(.google)
            }
        } else {
            state.lock = ServiceLock(cause: event, affectedPaths: [path],
                                     googleEvents: path.service == .google ? [path.family: event] : nil)
            save(state.lock, as: "lock", for: path.service)
            state.announce = true
            enforce(path.service)
        }
    }

    private func clearLock(for service: GuardService) {
        guard let state = services[service] else { return }
        state.lock = nil
        state.announce = false
        state.pending = false
        state.failures.removeAll()
        save(state.lock, as: "lock", for: service)
    }

    private func enforceLockedServices() {
        guard armed else { return }
        for service in GuardService.allCases where services[service]?.lock != nil { enforce(service) }
    }

    private func whitelistKey(_ id: String) -> String { "allowIPv4Entry." + id }

    private var enabledEntries: Set<String> {
        Set(AgentCloser.googleIPv4Entries.map(\.id).filter { defaults.bool(forKey: whitelistKey($0)) })
    }

    private func enforce(_ service: GuardService) {
        guard armed, let state = services[service], state.lock != nil else { return }
        if state.enforcing {
            state.pending = true
            return
        }
        state.enforcing = true
        let announce = state.announce
        state.announce = false
        Task {
            defer {
                state.enforcing = false
                if state.pending {
                    state.pending = false
                    enforce(service)
                }
            }
            guard armed, let trigger = state.lock?.actionCause else { return }
            let policy: @MainActor @Sendable () -> Set<String>? = { [self] in
                guard armed, let lock = state.lock,
                      service != .google || lock.actionCause.path.family == trigger.path.family else { return nil }
                return lock.ipv6Exceptions(enabled: enabledEntries)
            }
            let report = await AgentCloser.closeRunning(for: service, policy: policy)
            let failures = Set(report.failed)
            let announceEmpty = announce && policy()?.isEmpty == true
            if announceEmpty || !report.closed.isEmpty || !failures.subtracting(state.failures).isEmpty {
                let event = GuardEvent(path: trigger.path, previous: announce ? trigger.previous : trigger.current,
                                       current: trigger.current, time: trigger.time,
                                       closed: report.closed, failed: report.failed)
                state.lastEvent = event
                save(event, as: "lastEvent", for: service)
                card.show(event)
            }
            state.failures = failures
        }
    }

    private func countries(_ service: GuardService, _ family: Int) -> String {
        let selected = paths.filter { $0.service == service && $0.family == family }
        guard !selected.isEmpty else { return watching && lastChecked == nil ? "…" : "—" }
        let values = selected.compactMap { latest[$0]?.country }
        if values.contains("CN") { return "CN" }
        let known = Set(values)
        guard !known.isEmpty else { return "?" }
        let label = known.count == 1 ? values[0] : "多地"
        return values.count == selected.count ? label : label + "?"
    }

    private var status: String {
        if !watching { return "示例预览" }
        return armed ? "自动关闭已开启" : "仅监测 · 自动关闭已暂停"
    }

    private func updateStatus() {
        guard let button = item?.button else { return }
        let locked = services.values.contains { $0.lock != nil }
        let pairs = GuardService.allCases.map { ($0, "\(countries($0, 4))/\(countries($0, 6))") }
        let summary = pairs.map { "\($0.0.title) \($0.1)" }.joined(separator: " · ")
        let help = watching ? "\(status)\(locked ? " · 已锁定" : "")\nIPv4 / IPv6　\(summary)" : status
        guard help != button.toolTip else { return }
        let shield = NSImage(systemSymbolName: locked ? "exclamationmark.shield.fill" : "shield",
                             accessibilityDescription: nil)
        button.title = watching ? "" : " 节点保护器"
        button.imagePosition = watching ? .imageOnly : .imageLeading
        button.image = watching ? statusImage(pairs, shield: shield) : shield
        button.image?.isTemplate = true
        button.toolTip = help
        button.setAccessibilityLabel("节点保护器 · " + help)
    }

    private func statusImage(_ pairs: [(GuardService, String)], shield: NSImage?) -> NSImage {
        let font = NSFont.menuBarFont(ofSize: 12)
        let groups = pairs.map { service, codes in
            let mark = serviceMarks[service]
            let label = NSAttributedString(string: mark == nil ? "\(service.title) \(codes)" : codes,
                                           attributes: [.font: font, .foregroundColor: NSColor.black])
            return (mark: mark, label: label)
        }
        let icon: CGFloat = 14, textGap: CGFloat = 3, groupGap: CGFloat = 7
        let leading = shield == nil ? 0 : icon + groupGap
        let width = groups.reduce(leading) {
            $0 + ($1.mark == nil ? 0 : icon + textGap) + ceil($1.label.size().width)
        } + CGFloat(groups.count - 1) * groupGap
        // A single template lets AppKit tint both marks and text for any menu bar background.
        return NSImage(size: NSSize(width: width, height: 18), flipped: false) { rect in
            var x: CGFloat = 0
            let iconY = (rect.height - icon) / 2
            if let shield {
                shield.draw(in: NSRect(x: x, y: iconY, width: icon, height: icon))
                x += leading
            }
            for (mark, label) in groups {
                if let mark {
                    mark.draw(in: NSRect(x: x, y: iconY, width: icon, height: icon))
                    x += icon + textGap
                }
                let size = label.size()
                label.draw(at: NSPoint(x: x, y: floor((rect.height - size.height) / 2)))
                x += ceil(size.width) + groupGap
            }
            return true
        }
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        entryRows.removeAll()
        @discardableResult
        func row(_ title: String, _ action: Selector? = nil, in target: NSMenu) -> NSMenuItem {
            let entry = NSMenuItem(title: title, action: action, keyEquivalent: "")
            entry.target = action == nil ? nil : self
            target.addItem(entry)
            return entry
        }
        row(status, in: menu)
        for service in GuardService.allCases {
            let locked = services[service]?.lock != nil
            let title = service.signalTitle
            let entry = row("\(title)    IPv4 \(countries(service, 4))    IPv6 \(countries(service, 6))"
                            + (locked ? "  · 已锁定" : ""), in: menu)
            let details = NSMenu(title: title)
            entry.submenu = details
            switch service {
            case .google:
                for app in AgentCloser.googleIPv4Entries {
                    let label = row("\(app.title)　\(entryStatuses[app.id] ?? "正在识别…")", in: details)
                    entryRows[app.id] = label
                    let toggle = row("允许 \(app.title) IPv4 入口忽略 IPv6", #selector(toggleIPv4Entry(_:)), in: details)
                    toggle.representedObject = app.id
                    toggle.state = defaults.bool(forKey: whitelistKey(app.id)) ? .on : .off
                }
                details.addItem(.separator())
            case .chatgpt: row("CN 时关闭 ChatGPT（含 Codex）", in: details)
            case .claude: row("CN 时关闭 Claude", in: details)
            }
            row(service.traceHost.map { "地区来自 " + $0 + " 网站入口" } ?? "地区来自 Google X-Country", in: details)
            for path in paths where path.service == service {
                let reading = latest[path]
                let line = row("\(path.route.title) · IPv\(path.family)　\(reading?.country ?? "未知")", in: details)
                var info: [String] = []
                if let ip = reading?.ip { info.append("出口 IP　" + ip) }
                if let ip = reading?.destinationIP { info.append("目标 IP　" + ip) }
                if let chain = reading?.clashChain, !chain.isEmpty { info.append("Clash　" + chain.joined(separator: " → ")) }
                if !info.isEmpty {
                    let more = NSMenu()
                    line.submenu = more
                    for text in info { row(text, in: more) }
                }
            }
            if services[service]?.lastEvent != nil {
                details.addItem(.separator())
                let last = row("查看最近一次提示", #selector(showLast(_:)), in: details)
                last.representedObject = service.rawValue
            }
        }
        if let lastChecked { row("最近检测  " + lastChecked.formatted(date: .omitted, time: .standard), in: menu) }
        menu.addItem(.separator())
        if !watching { row("仅监测出口", #selector(monitorOnly), in: menu) }
        row(armed ? "暂停自动关闭" : "启用自动关闭", #selector(toggleProtection), in: menu)
        row("预览提示卡", #selector(showPreview), in: menu)
        menu.addItem(.separator())
        row("退出节点保护器", #selector(quit), in: menu)
        refreshEntryRows()
    }

    private func refreshEntryRows() {
        guard !readingEntries else { return }
        readingEntries = true
        Task {
            let current = await AgentCloser.ipv4EntryStatuses()
            for app in AgentCloser.googleIPv4Entries {
                let status = current[app.id] ?? "未运行"
                entryStatuses[app.id] = status
                entryRows[app.id]?.title = "\(app.title)　\(status)"
            }
            readingEntries = false
        }
    }

    @objc private func toggleIPv4Entry(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String else { return }
        let key = whitelistKey(id)
        defaults.set(!defaults.bool(forKey: key), forKey: key)
        sender.state = defaults.bool(forKey: key) ? .on : .off
        enforce(.google)
    }

    @objc private func monitorOnly() {
        armed = false
        defaults.set(false, forKey: "armed")
        for service in GuardService.allCases { clearLock(for: service) }
        startWatching()
    }

    @objc private func toggleProtection() {
        armed.toggle()
        defaults.set(armed, forKey: "armed")
        for service in GuardService.allCases { clearLock(for: service) }
        if watching { networkChanged() } else { startWatching() }
    }

    @objc private func showPreview() { card.show(.sample, preview: true) }
    @objc private func showLast(_ sender: NSMenuItem) {
        if let raw = sender.representedObject as? String, let service = GuardService(rawValue: raw),
           let last = services[service]?.lastEvent { card.show(last) }
    }
    @objc private func quit() { NSApp.terminate(nil) }
}

@main
private struct NodeGuard {
    @MainActor static func main() {
        let app = NSApplication.shared
        let delegate = GuardController()
        app.setActivationPolicy(.accessory)
        app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }
}
