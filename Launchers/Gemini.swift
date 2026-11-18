import AppKit
import Foundation

let originalID = "com.google.GeminiMacOS"
let originalURL = URL(fileURLWithPath: "/Applications/Gemini.app")
let coreURL = URL(fileURLWithPath: "/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo")

struct StartError: LocalizedError {
    let text: String
    init(_ text: String) { self.text = text }
    var errorDescription: String? { text }
}

func capture(_ path: String, _ arguments: [String]) throws -> Data {
    let task = Process()
    let pipe = Pipe()
    task.executableURL = URL(fileURLWithPath: path)
    task.arguments = arguments
    task.standardOutput = pipe
    task.standardError = FileHandle.nullDevice
    try task.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    task.waitUntilExit()
    guard task.terminationStatus == 0 else { throw StartError("命令未成功：" + path) }
    return data
}

func clash(_ endpoint: String) throws -> [String: Any] {
    let socket = "/var/run/clash-verge-service/users/\(getuid())/verge-mihomo.sock"
    let raw = try capture("/usr/bin/curl", ["-q", "--noproxy", "*", "--max-time", "3",
        "--unix-socket", socket, "-fsS", "http://localhost/" + endpoint])
    return try JSONSerialization.jsonObject(with: raw) as? [String: Any] ?? [:]
}

final class Launcher: NSObject, NSApplicationDelegate {
    var core: Process?
    var temp: URL?
    var target: Process?
    var bridge: Process?
    var closing = false

    func fail(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "Gemini IPv4"
        alert.informativeText = message
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
        NSApp.terminate(nil)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if !NSRunningApplication.runningApplications(withBundleIdentifier: originalID).isEmpty {
            fail("Gemini 已由其他入口打开。请保存工作并完全退出，再点这个图标。")
            return
        }
        do {
            let settings = try clash("configs")
            guard let tun = settings["tun"] as? [String: Any], tun["enable"] as? Bool == true,
                  let device = tun["device"] as? String, !device.isEmpty else {
                throw StartError("请先打开 Clash Verge 的 TUN，再启动 Gemini。")
            }
            let port = Int.random(in: 49152...65535)
            try startCore(port: port, device: device)
            try startBridge(port: port)
        } catch { fail(error.localizedDescription) }
    }

    func startBridge(port: Int) throws {
        let processes = originalID + ";" + originalID + ".*;/Applications/Gemini.app/*"
        // ProxyBridge chooses a UDP rule by process before it knows the remote port.
        // Forward datagrams to mihomo so it can accept DNS and reject other UDP.
        let rules: [[String: Any]] = [["processNames": processes, "targetHosts": "*",
            "targetPorts": "*", "protocol": "BOTH", "action": "IPv4", "enabled": true]]
        let profile: [String: Any] = ["name": "Gemini IPv4", "dnsEnabled": false,
            "proxyConfigs": [["id": "IPv4", "type": "socks5", "host": "127.0.0.1", "port": port,
                              "sendDomain": false] as [String: Any]], "proxyRules": rules]
        let data = try JSONSerialization.data(withJSONObject: profile)
        let task = Process()
        let input = Pipe()
        let output = Pipe()
        task.executableURL = URL(fileURLWithPath: "/Applications/ProxyBridge.app/Contents/MacOS/ProxyBridge")
        task.arguments = ["--profile", "-"]
        task.standardInput = input
        task.standardOutput = output
        task.standardError = output
        try task.run()
        bridge = task
        try input.fileHandleForWriting.write(contentsOf: data)
        try input.fileHandleForWriting.close()

        Task { @MainActor in
            var applied = false
            var detail = ""
            do {
                for try await line in output.fileHandleForReading.bytes.lines {
                    if line.hasPrefix("Profile \"Gemini IPv4\":") {
                        applied = line.hasSuffix("1 proxies, 1 rules applied")
                    }
                    if line.hasPrefix("ERROR:") || line.hasPrefix("warning:") { detail = line }
                    if line.hasPrefix("Redirecting traffic.") && target == nil {
                        guard applied, task.isRunning else { throw StartError("Gemini 的 IPv4 规则未生效。\n" + detail) }
                        try startGemini()
                    }
                }
                if !closing { throw StartError("ProxyBridge 已停止。\n" + detail) }
            } catch {
                if !closing {
                    if let app = target, app.isRunning { app.terminate() }
                    fail(error.localizedDescription)
                }
            }
        }
    }

    func startGemini() throws {
        guard let executable = Bundle(url: originalURL)?.executableURL else {
            throw StartError("未找到 /Applications/Gemini.app。")
        }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        let profile = #"(version 1)(allow default)(deny network-outbound (remote ip6 "*:*"))"#
        task.arguments = ["-p", profile, executable.path]
        task.terminationHandler = { _ in DispatchQueue.main.async { NSApp.terminate(nil) } }
        try task.run()
        target = task
        NSRunningApplication(processIdentifier: task.processIdentifier)?.activate(options: [])
    }

    func startCore(port: Int, device: String) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        temp = directory
        let config: [String: Any] = [
            "socks-port": port, "allow-lan": false, "ipv6": false, "mode": "rule",
            "log-level": "silent", "geo-auto-update": false, "find-process-mode": "off",
            "interface-name": device,
            "sniffer": ["enable": true, "parse-pure-ip": true, "override-destination": true,
                        "sniff": ["TLS": ["ports": [443]], "HTTP": ["ports": [80]]]],
            "dns": ["enable": true, "ipv6": false, "enhanced-mode": "redir-host",
                    "nameserver": ["https://8.8.8.8/dns-query"], "direct-nameserver": ["https://8.8.8.8/dns-query"]],
            "proxies": [["name": "IPv4", "type": "direct", "ip-version": "ipv4", "interface-name": device],
                        ["name": "GeminiDNS", "type": "dns"]],
            "rules": ["DST-PORT,53,GeminiDNS", "NETWORK,UDP,REJECT",
                      "IP-CIDR,198.18.0.0/15,REJECT,no-resolve", "IP-CIDR6,::/0,REJECT,no-resolve", "MATCH,IPv4"]
        ]
        let encoded = try JSONSerialization.data(withJSONObject: config, options: [.withoutEscapingSlashes]).base64EncodedString()
        let task = Process()
        task.executableURL = coreURL
        task.arguments = ["-d", directory.path, "-config", encoded]
        let diagnostics = Pipe()
        task.standardOutput = diagnostics
        task.standardError = diagnostics
        try task.run()
        core = task
        // Confirm the listener belongs to our process before handing it the application's traffic.
        for _ in 0..<35 {
            guard task.isRunning else { break }
            if let output = try? capture("/usr/sbin/lsof", ["-nP", "-a", "-p", String(task.processIdentifier),
                    "-iTCP:\(port)", "-sTCP:LISTEN", "-Fn"]),
               String(decoding: output, as: UTF8.self).contains("n127.0.0.1:\(port)\n") {
                diagnostics.fileHandleForReading.readabilityHandler = { handle in
                    if handle.availableData.isEmpty { handle.readabilityHandler = nil }
                }
                return
            }
            Thread.sleep(forTimeInterval: 0.12)
        }
        if task.isRunning { task.terminate() }
        task.waitUntilExit()
        let detail = String(decoding: diagnostics.fileHandleForReading.readDataToEndOfFile().suffix(1200), as: UTF8.self)
        throw StartError("本地 IPv4 代理未能启动（退出码 \(task.terminationStatus)）。\n" + detail)
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if let task = target, task.isRunning {
            NSRunningApplication(processIdentifier: task.processIdentifier)?.activate(options: [])
        }
        return false
    }

    func applicationWillTerminate(_ note: Notification) {
        closing = true
        if let app = target, app.isRunning { app.terminate(); app.waitUntilExit() }
        if let task = bridge, task.isRunning { task.terminate(); task.waitUntilExit() }
        if let task = core, task.isRunning { task.terminate(); task.waitUntilExit() }
        if let directory = temp { try? FileManager.default.removeItem(at: directory) }
    }
}

let app = NSApplication.shared
let launcher = Launcher()
app.delegate = launcher
app.run()
