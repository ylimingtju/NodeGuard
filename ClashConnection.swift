import Darwin
import Foundation
import Network

enum ClashConnection {
    static func freeSourcePort() -> Int? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout.size(ofValue: address))
        address.sin_family = sa_family_t(AF_INET)
        address.sin_len = UInt8(length)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, length) == 0 && getsockname(fd, $0, &length) == 0
            }
        }
        return bound ? Int(UInt16(bigEndian: address.sin_port)) : nil
    }

    private static func controller() -> (socket: String, secret: String)? {
        let path = NSHomeDirectory() + "/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml"
        var values: [String: String] = [:]
        if let config = try? String(contentsOfFile: path, encoding: .utf8) {
            config.enumerateLines { line, stop in
                guard let colon = line.firstIndex(of: ":") else { return }
                let key = String(line[..<colon])
                guard key == "secret" || key == "external-controller-unix" else { return }
                let raw = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                if raw.first == "\"" {
                    values[key] = try? JSONDecoder().decode(String.self, from: Data(raw.utf8))
                } else if raw.first == "'", raw.last == "'", raw.count >= 2 {
                    values[key] = raw.dropFirst().dropLast().replacingOccurrences(of: "''", with: "'")
                } else {
                    values[key] = raw.components(separatedBy: " #")[0]
                }
                stop = values.count == 2
            }
        }
        let paths = ["/var/run/clash-verge-service/users/\(getuid())/verge-mihomo.sock",
                     values["external-controller-unix"] ?? ""]
        let secret = values["secret"] ?? ""
        guard secret.utf8.count <= 2048, secret.rangeOfCharacter(from: .controlCharacters) == nil,
              let sock = paths.first(where: {
                  $0.hasPrefix("/") && (try? FileManager.default.attributesOfItem(atPath: $0)[.type]) as? FileAttributeType == .typeSocket
              }) else { return nil }
        return (sock, secret)
    }

    private static func snapshot(_ control: (socket: String, secret: String)) -> [[String: Any]]? {
        let curl = Process()
        let input = Pipe(), output = Pipe()
        curl.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        curl.arguments = ["--disable", "--silent", "--fail", "--noproxy", "*", "--max-time", "0.4",
                          "--max-filesize", "8388608", "--unix-socket", control.socket,
                          "--header", "@-", "http://localhost/connections"]
        curl.environment = [:]
        curl.standardInput = input
        curl.standardOutput = output
        curl.standardError = FileHandle.nullDevice
        if !control.secret.isEmpty {
            input.fileHandleForWriting.write(Data("Authorization: Bearer \(control.secret)\n".utf8))
        }
        input.fileHandleForWriting.closeFile()
        do { try curl.run() } catch { return nil }
        let data = try? output.fileHandleForReading.readToEnd()
        curl.waitUntilExit()
        guard curl.terminationStatus == 0, let data,
              let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        return json["connections"] as? [[String: Any]]
    }

    static func inspect(sourcePort: Int, destinationIP: String, whileRunning: () -> Bool) -> [String]? {
        guard let expectedIP = IPv4Address(destinationIP)?.rawValue ?? IPv6Address(destinationIP)?.rawValue,
              let control = controller() else { return nil }
        let mappedLocal = IPv6Address("::ffff:127.0.0.1")!.rawValue
        let deadline = ProcessInfo.processInfo.systemUptime + 1.2
        while whileRunning() && ProcessInfo.processInfo.systemUptime < deadline {
            guard let rows = snapshot(control) else { return nil }
            for row in rows {
                guard let meta = row["metadata"] as? [String: Any],
                      String(describing: meta["sourcePort"] ?? "") == String(sourcePort),
                      String(describing: meta["destinationPort"] ?? "") == "443",
                      let src = meta["sourceIP"] as? String,
                      src == "127.0.0.1" || IPv6Address(src)?.rawValue == mappedLocal,
                      let dst = meta["destinationIP"] as? String,
                      (IPv4Address(dst)?.rawValue ?? IPv6Address(dst)?.rawValue) == expectedIP,
                      let chains = row["chains"] as? [String], !chains.isEmpty else { continue }
                return chains
            }
            Thread.sleep(forTimeInterval: 0.045)
        }
        return nil
    }
}
