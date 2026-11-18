import AppKit
import Foundation

let originalID = "com.google.antigravity"
let originalURL = URL(fileURLWithPath: "/Applications/Antigravity.app")
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
    var target: NSRunningApplication?

    func fail(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "Antigravity IPv4"
        alert.informativeText = message
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
        NSApp.terminate(nil)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if !NSRunningApplication.runningApplications(withBundleIdentifier: originalID).isEmpty {
            fail("Antigravity 已由其他入口打开。请保存工作并完全退出，再点这个图标。")
            return
        }
        do {
            let settings = try clash("configs")
            guard let tun = settings["tun"] as? [String: Any], tun["enable"] as? Bool == true,
                  let device = tun["device"] as? String, !device.isEmpty else {
                throw StartError("请先打开 Clash Verge 的 TUN，再启动 Antigravity。")
            }
            let port = Int.random(in: 49152...65535)
            try startCore(port: port, device: device)
            let proxy = "http://127.0.0.1:\(port)"
            let options = NSWorkspace.OpenConfiguration()
            options.arguments = ["--proxy-server=" + proxy, "--disable-quic"]
            var env = ProcessInfo.processInfo.environment
            for key in ["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy"] {
                env[key] = proxy
            }
            for key in ["NO_PROXY","no_proxy"] { env[key] = "localhost,127.0.0.1,::1" }
            options.environment = env
            NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(didQuit(_:)),
                name: NSWorkspace.didTerminateApplicationNotification, object: nil)
            NSWorkspace.shared.openApplication(at: originalURL, configuration: options) { app, error in
                DispatchQueue.main.async {
                    guard let app = app, !app.isTerminated else {
                        self.fail(error?.localizedDescription ?? "Antigravity 启动失败。"); return
                    }
                    self.target = app
                }
            }
        } catch { fail(error.localizedDescription) }
    }

    func startCore(port: Int, device: String) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        temp = directory
        let config: [String: Any] = [
            "port": port, "allow-lan": false, "ipv6": false, "mode": "rule",
            "log-level": "silent", "geo-auto-update": false, "find-process-mode": "off",
            "interface-name": device,
            "dns": ["enable": true, "ipv6": false, "enhanced-mode": "redir-host",
                    "nameserver": ["https://8.8.8.8/dns-query"], "direct-nameserver": ["https://8.8.8.8/dns-query"]],
            "proxies": [["name": "IPv4", "type": "direct", "ip-version": "ipv4", "interface-name": device]],
            "rules": ["MATCH,IPv4"]
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

    @objc func didQuit(_ note: Notification) {
        if let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
           app.bundleIdentifier == originalID, app.processIdentifier == target?.processIdentifier {
            NSApp.terminate(nil)
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if target != nil { NSWorkspace.shared.open(originalURL) }
        return false
    }

    func applicationWillTerminate(_ note: Notification) {
        if let task = core, task.isRunning { task.terminate(); task.waitUntilExit() }
        if let directory = temp { try? FileManager.default.removeItem(at: directory) }
    }
}

let app = NSApplication.shared
let launcher = Launcher()
app.delegate = launcher
app.run()
