import Foundation

enum GuardService: String, Codable, CaseIterable {
    case google, chatgpt, claude

    var title: String {
        switch self {
        case .google: return "Google"
        case .chatgpt: return "ChatGPT"
        case .claude: return "Claude"
        }
    }

    var traceHost: String? {
        switch self {
        case .google: return nil
        case .chatgpt: return "chatgpt.com"
        case .claude: return "claude.ai"
        }
    }

    var signalTitle: String { traceHost == nil ? title : title + " 入口" }
}

enum ProbeRoute: String, Codable {
    case local, clash, system

    var title: String {
        switch self {
        case .local: return "本机路由"
        case .clash: return "Clash 代理"
        case .system: return "系统代理"
        }
    }
}

struct ProbePath: Hashable, Codable {
    let service: GuardService
    let family: Int
    let route: ProbeRoute
}

struct ProbeReading: Codable {
    // Google returns X-Country without echoing the client's public address.
    let ip: String?
    let country: String
    let destinationIP: String?
    var clashChain: [String]? = nil
}

struct ServiceLock: Codable {
    var cause: GuardEvent
    var affectedPaths: Set<ProbePath>
    // Older versions stored just one event, even when both families had returned CN.
    var googleEvents: [Int: GuardEvent]?

    var actionCause: GuardEvent {
        guard cause.path.service == .google,
              let path = affectedPaths.min(by: { $0.family < $1.family }) else { return cause }
        if let event = googleEvents?[path.family] { return event }
        if cause.path.family == path.family { return cause }
        return GuardEvent(path: path, previous: nil, current: ProbeReading(ip: nil, country: "CN", destinationIP: nil),
                          time: nil, closed: [], failed: [])
    }

    func ipv6Exceptions(enabled: Set<String>) -> Set<String> {
        guard cause.path.service == .google, !affectedPaths.isEmpty,
              affectedPaths.allSatisfy({ $0.family == 6 }) else { return [] }
        return enabled
    }

    // A timeout in this family keeps its lock. A result from the other family cannot clear it.
    mutating func recoverGoogleFamily(_ family: Int, active: [ProbePath], safe: Set<ProbePath>) -> Bool {
        let current = active.filter { $0.service == .google && $0.family == family }
        guard affectedPaths.contains(where: { $0.family == family }),
              !current.isEmpty, current.allSatisfy(safe.contains) else { return false }
        affectedPaths = affectedPaths.filter { $0.family != family }
        googleEvents?.removeValue(forKey: family)
        return true
    }
}
