import CFNetwork
import Darwin
import Foundation
import SystemConfiguration

enum EgressProbe {
    private static let googleURL = URL(string: "https://clientservices.googleapis.com/chrome-variations/seed?osname=mac&channel=stable")!
    private static let clashProxy = "http://127.0.0.1:7897"
    private static let countries = Set(Locale.Region.isoRegions.map(\.identifier))

    private static func googleAddress(_ family: Int) -> String {
        family == 6 ? "2404:6800:400b:c005::66" : "142.250.21.139"
    }

    private static func endpoint(_ service: GuardService) -> URL {
        guard let host = service.traceHost else { return googleURL }
        return URL(string: "https://\(host)/cdn-cgi/trace")!
    }

    private static func clashIsListening() -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { return false }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        address.sin_port = UInt16(7897).bigEndian
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if result == 0 { return true }
        guard errno == EINPROGRESS else { return false }
        var event = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        var error: Int32 = 0
        var size = socklen_t(MemoryLayout<Int32>.size)
        return poll(&event, 1, 100) > 0 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0
    }

    static func paths() -> [ProbePath] {
        let localFamilies = [4, 6].filter { !explicitlyDisabled($0) }
        let clash = clashIsListening()
        var result: [ProbePath] = []
        for service in GuardService.allCases {
            let configured = systemRoute(target: endpoint(service), deadline: 0, resolvePAC: false)
            var addSystem = configured != .direct
            if clash, case .proxy(let value) = configured, let u = URL(string: value),
               u.port == 7897, ["localhost", "127.0.0.1", "::1", "[::1]"].contains(u.host?.lowercased() ?? "") {
                addSystem = false
            }
            for family in [4, 6] {
                if localFamilies.contains(family) { result.append(ProbePath(service: service, family: family, route: .local)) }
                if clash { result.append(ProbePath(service: service, family: family, route: .clash)) }
                if addSystem { result.append(ProbePath(service: service, family: family, route: .system)) }
            }
        }
        return result
    }

    private static func explicitlyDisabled(_ family: Int) -> Bool {
        let other = family == 6 ? 4 : 6
        let key = "State:/Network/Global/IPv\(other)" as CFString
        guard let state = SCDynamicStoreCopyValue(nil, key) as? [String: Any],
              let id = state["PrimaryService"] as? String,
              let prefs = SCPreferencesCreate(nil, "节点保护器" as CFString, nil),
              let service = SCNetworkServiceCopy(prefs, id as CFString),
              let proto = SCNetworkServiceCopyProtocol(service, "IPv\(family)" as CFString)
        else { return false }
        let config = SCNetworkProtocolGetConfiguration(proto) as? [String: Any]
        let method = config?["ConfigMethod"] as? String
        guard !SCNetworkProtocolGetEnabled(proto) || method == "Off" || method == "LinkLocal" else { return false }

        // A tunnel can still install a usable route when Wi-Fi has this family disabled.
        // Connecting an unbound datagram socket asks the kernel to choose a route;
        // no datagram is sent.
        var hints = addrinfo()
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV
        hints.ai_socktype = SOCK_DGRAM
        var dest: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(googleAddress(family), "443", &hints, &dest) == 0,
              let dest else { return false }
        defer { freeaddrinfo(dest) }
        let fd = socket(dest.pointee.ai_family, SOCK_DGRAM, 0)
        guard fd >= 0 else { return errno == EAFNOSUPPORT }
        defer { close(fd) }
        if connect(fd, dest.pointee.ai_addr, dest.pointee.ai_addrlen) == 0 { return false }
        return [ENETUNREACH, EHOSTUNREACH, EADDRNOTAVAIL, EAFNOSUPPORT].contains(errno)
    }

    private enum Route: Equatable {
        case direct
        case proxy(String)
    }

    private final class PACResult {
        var first: [String: Any]?
    }

    private static func evaluatePAC(_ proxy: [String: Any], target: URL, deadline: TimeInterval) -> [String: Any]? {
        let result = PACResult()
        var context = CFStreamClientContext(version: 0, info: Unmanaged.passUnretained(result).toOpaque(),
                                            retain: nil, release: nil, copyDescription: nil)
        let callback: CFProxyAutoConfigurationResultCallback = { info, proxies, error in
            if error == nil {
                Unmanaged<PACResult>.fromOpaque(info).takeUnretainedValue().first =
                    (proxies as? [[String: Any]])?.first
            }
        }
        let source: CFRunLoopSource
        if let script = proxy[kCFProxyAutoConfigurationJavaScriptKey as String] as? String {
            source = CFNetworkExecuteProxyAutoConfigurationScript(script as CFString, target as CFURL, callback, &context)
        } else if let url = proxy[kCFProxyAutoConfigurationURLKey as String] as? URL {
            source = CFNetworkExecuteProxyAutoConfigurationURL(url as CFURL, target as CFURL, callback, &context)
        } else {
            return nil
        }
        // Only this source is scheduled in this mode on the probe's worker thread.
        let mode = "EgressProbe.PAC" as CFString
        CFRunLoopAddSource(CFRunLoopGetCurrent(), source, CFRunLoopMode(mode))
        defer {
            CFRunLoopSourceInvalidate(source)
            withExtendedLifetime(result) {}
        }
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0 else { return nil }
        CFRunLoopRunInMode(CFRunLoopMode(mode), remaining, true)
        return result.first
    }

    private static func systemRoute(target: URL, deadline: TimeInterval, resolvePAC: Bool = true) -> Route? {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue(),
              let proxies = CFNetworkCopyProxiesForURL(target as CFURL, settings).takeRetainedValue() as? [[String: Any]],
              var proxy = proxies.first,
              var type = proxy[kCFProxyTypeKey as String] as? String else { return nil }
        let fromPAC = type == kCFProxyTypeAutoConfigurationURL as String || type == kCFProxyTypeAutoConfigurationJavaScript as String
        if fromPAC {
            guard resolvePAC, let selected = evaluatePAC(proxy, target: target, deadline: deadline),
                  let selectedType = selected[kCFProxyTypeKey as String] as? String else { return nil }
            if selectedType == kCFProxyTypeNone as String { return .direct }
            proxy = selected
            type = selectedType
        }
        var hostValue = proxy[kCFProxyHostNameKey as String]
        var portValue = proxy[kCFProxyPortNumberKey as String]
        if type == kCFProxyTypeNone as String, let manual = settings as? [String: Any] {
            // A system bypass on this one test host shouldn't hide the manual proxy's exit.
            if (manual[kCFNetworkProxiesHTTPSEnable as String] as? NSNumber)?.boolValue == true {
                type = kCFProxyTypeHTTPS as String
                hostValue = manual[kCFNetworkProxiesHTTPSProxy as String]
                portValue = manual[kCFNetworkProxiesHTTPSPort as String]
            } else if (manual[kCFNetworkProxiesSOCKSEnable as String] as? NSNumber)?.boolValue == true {
                type = kCFProxyTypeSOCKS as String
                hostValue = manual[kCFNetworkProxiesSOCKSProxy as String]
                portValue = manual[kCFNetworkProxiesSOCKSPort as String]
            }
        }
        if type == kCFProxyTypeNone as String { return .direct }
        guard let host = hostValue as? String, !host.isEmpty,
              let port = portValue as? Int, (1...65535).contains(port)
        else { return nil }
        var url = URLComponents()
        if type == kCFProxyTypeHTTP as String || type == kCFProxyTypeHTTPS as String {
            // The HTTPS system preference selects an HTTP CONNECT proxy for HTTPS URLs;
            // PAC can explicitly request TLS to the proxy with the HTTPS directive.
            url.scheme = fromPAC && type == kCFProxyTypeHTTPS as String ? "https" : "http"
        } else if type == kCFProxyTypeSOCKS as String {
            url.scheme = "socks5h"
        } else {
            return nil
        }
        url.host = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        url.port = port
        return url.string.map(Route.proxy)
    }

    private static var now: TimeInterval { ProcessInfo.processInfo.systemUptime }

    static func read(_ path: ProbePath) async -> ProbeReading? {
        guard !Task.isCancelled, [4, 6].contains(path.family) else { return nil }
        let deadline = now + 3
        let value: ProbeReading? = await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                continuation.resume(returning: fetch(path, deadline: deadline))
            }
        }
        return Task.isCancelled ? nil : value
    }

    private final class ChainResult {
        let group = DispatchGroup()
        var chain: [String]?
    }

    // Keep the URL hostname for certificate verification, SNI and HTTP Host.
    // --connect-to uses the requested numeric destination even inside a proxy tunnel.
    private static func request(_ url: URL, address: String, route: Route, deadline: TimeInterval,
                                options: [String], headersOnly: Bool = false, inspectClash: Bool = false) -> (data: Data, chain: [String]?)? {
        guard let host = url.host else { return nil }
        let v6 = address.contains(":")
        let destination = v6 ? "[\(address)]" : address
        let remaining = deadline - now
        guard remaining >= 0.001 else { return nil }
        var args = ["--disable", "--silent", "--fail", "--globoff", "--http1.1", "--user-agent", "",
                    "--connect-to", "\(host):443:\(destination):443",
                    "--max-time", String(format: "%.3f", locale: Locale(identifier: "en_US_POSIX"), remaining)]
        switch route {
        case .direct: args += ["--proxy", "", "--noproxy", "*", v6 ? "--ipv6" : "--ipv4"]
        case .proxy(let proxy): args += ["--proxy", proxy, "--noproxy", ""]
        }
        if headersOnly {
            // Do a GET, but stop at the response size limit as soon as headers arrive.
            args += ["--suppress-connect-headers", "--dump-header", "-", "--output", "/dev/null", "--max-filesize", "1"]
        } else {
            args += ["--max-filesize", "16384"]
        }
        let sourcePort = inspectClash ? ClashConnection.freeSourcePort() : nil
        if let sourcePort { args += ["--local-port", String(sourcePort)] }
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        process.arguments = args + options + ["--write-out", "\n%{response_code}", url.absoluteString]
        process.environment = [:]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return nil }
        let observation = ChainResult()
        if let sourcePort {
            observation.group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                defer { observation.group.leave() }
                observation.chain = ClashConnection.inspect(sourcePort: sourcePort, destinationIP: address) {
                    process.isRunning && now < deadline
                }
            }
        }
        let data = try? output.fileHandleForReading.readToEnd()
        process.waitUntilExit()
        // curl status 63 means --max-filesize stopped the Google seed body.
        guard process.terminationStatus == 0 || (headersOnly && process.terminationStatus == 63),
              let data, data.count <= 65536, data.suffix(4).elementsEqual("\n200".utf8) else { return nil }
        // Optional metadata must never delay reading or reject a valid service response.
        let joined = observation.group.wait(timeout: .now() + .milliseconds(60)) == .success
        return (data.dropLast(4), joined ? observation.chain : nil)
    }

    private struct DNSReply: Decodable {
        let Status: Int
        let Answer: [Answer]?
        struct Answer: Decodable { let type: Int; let TTL: Int; let data: String }
    }
    private static let dnsLock = NSLock()
    private static var traceAddresses: [String: (address: String, expiry: TimeInterval)] = [:]

    private static func traceAddress(host: String, family: Int, route: Route, deadline: TimeInterval) -> String? {
        let routeID: String
        switch route {
        case .direct: routeID = "direct"
        case .proxy(let url): routeID = url
        }
        let key = "\(host) \(family) \(routeID)"
        dnsLock.lock()
        let cached = traceAddresses[key]
        dnsLock.unlock()
        if let cached, cached.expiry > now { return cached.address }
        // Resolve the real record over authenticated DNS-over-HTTPS, without using a
        // synthetic address returned by Clash Fake-IP. The resolver supplies no region signal.
        let record = family == 6 ? 28 : 1
        let dns = URL(string: "https://dns.google/resolve?name=\(host)&type=\(record)")!
        let resolverAddress = family == 6 ? "2001:4860:4860::8888" : "8.8.8.8"
        guard let data = request(dns, address: resolverAddress, route: route, deadline: deadline, options: []),
              let reply = try? JSONDecoder().decode(DNSReply.self, from: data.data), reply.Status == 0,
              let answer = reply.Answer?.first(where: { $0.type == record && validIP($0.data, family: family) })
        else { return nil }
        dnsLock.lock()
        traceAddresses[key] = (answer.data, now + Double(max(0, min(answer.TTL, 300))))
        dnsLock.unlock()
        return answer.data
    }

    private static func validIP(_ ip: String, family: Int) -> Bool {
        var address = in6_addr()
        return inet_pton(family == 6 ? AF_INET6 : AF_INET, ip, &address) == 1
    }

    private static func country(_ text: Substring) -> String? {
        let code = text.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        return code.count == 2 && countries.contains(code) && !["XX", "ZZ"].contains(code) ? code : nil
    }

    private static func fetch(_ path: ProbePath, deadline: TimeInterval) -> ProbeReading? {
        let target = endpoint(path.service)
        let route: Route
        switch path.route {
        case .local: route = .direct
        case .clash: route = .proxy(clashProxy)
        case .system:
            guard let selected = systemRoute(target: target, deadline: deadline) else { return nil }
            route = selected
        }
        switch path.service {
        case .google:
            let destination = googleAddress(path.family)
            guard let data = request(target, address: destination, route: route, deadline: deadline,
                                     options: [], headersOnly: true, inspectClash: path.route == .clash),
                  let text = String(data: data.data, encoding: .isoLatin1),
                  let finalHeaders = text.components(separatedBy: "\r\n\r\n").last(where: { $0.hasPrefix("HTTP/") })
            else { return nil }
            let values = finalHeaders.split(whereSeparator: \.isNewline).compactMap { line -> Substring? in
                guard let colon = line.firstIndex(of: ":"),
                      line[..<colon].lowercased() == "x-country" else { return nil }
                return line[line.index(after: colon)...]
            }
            guard values.count == 1, let code = country(values[0]) else { return nil }
            var reading = ProbeReading(ip: nil, country: code, destinationIP: destination)
            reading.clashChain = data.chain
            return reading
        case .chatgpt, .claude:
            guard let host = target.host,
                  let destination = traceAddress(host: host, family: path.family, route: route, deadline: deadline),
                  let data = request(target, address: destination, route: route, deadline: deadline, options: [],
                                     inspectClash: path.route == .clash),
                  let text = String(data: data.data, encoding: .utf8) else { return nil }
            let lines = text.split(whereSeparator: \.isNewline)
            guard lines.contains(where: { $0 == "h=\(host)" }),
                  let ipLine = lines.first(where: { $0.hasPrefix("ip=") }),
                  let locLine = lines.first(where: { $0.hasPrefix("loc=") }),
                  let code = country(locLine.dropFirst(4)) else { return nil }
            let ip = String(ipLine.dropFirst(3))
            guard validIP(ip, family: path.family) else { return nil }
            var reading = ProbeReading(ip: ip, country: code, destinationIP: destination)
            reading.clashChain = data.chain
            return reading
        }
    }
}
