import AppKit
import SwiftUI

struct GuardEvent: Codable {
    let path: ProbePath
    let previous: ProbeReading?
    let current: ProbeReading
    let time: Date?
    let closed: [String]
    let failed: [String]

    static var sample: GuardEvent {
        GuardEvent(path: ProbePath(service: .google, family: 6, route: .clash),
                   previous: nil,
                   current: ProbeReading(ip: nil, country: "CN", destinationIP: "2404:6800:400b:c005::66"),
                   time: Date(), closed: ["Gemini", "Antigravity"], failed: [])
    }
}

private final class NoticePanel: NSPanel {
    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
}

private final class CardHost: NSHostingView<CardContent> {
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}

@MainActor
final class EventCard {
    private let panel = NoticePanel(contentRect: .zero,
                                    styleMask: [.borderless, .nonactivatingPanel],
                                    backing: .buffered, defer: false)
    private var dismissal: Task<Void, Never>?
    private var event: GuardEvent?
    private var preview = false
    private var expanded = false
    private var pending: [(GuardEvent, Bool)] = []
    private var screen: NSScreen?

    init() {
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.isFloatingPanel = true
        panel.level = .statusBar
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .ignoresCycle]
        panel.setAccessibilityLabel("节点保护器出口提示")
    }

    func show(_ event: GuardEvent, preview: Bool = false) {
        if panel.isVisible {
            pending.append((event, preview))
            return
        }
        self.event = event
        self.preview = preview
        expanded = false
        screen = NSScreen.screens.first { $0.frame.contains(NSEvent.mouseLocation) } ?? NSScreen.main
        render()
        panel.orderFrontRegardless()
        dismissal = Task { [weak self] in
            do { try await Task.sleep(nanoseconds: 8_000_000_000) }
            catch { return }
            self?.hide()
        }
    }

    private func hide() {
        dismissal?.cancel()
        panel.orderOut(nil)
        if !pending.isEmpty {
            let (next, preview) = pending.removeFirst()
            show(next, preview: preview)
        }
    }

    private func render() {
        guard let event, let frame = (screen ?? NSScreen.main)?.visibleFrame else { return }
        let host = CardHost(rootView: CardContent(event: event, preview: preview, expanded: expanded,
                                                  toggle: { [weak self] in
            guard let self else { return }
            self.dismissal?.cancel()
            self.expanded.toggle()
            self.render()
        }, close: { [weak self] in self?.hide() }))
        let size = host.fittingSize
        panel.contentView = host
        panel.setFrame(NSRect(x: frame.maxX - size.width - 16, y: frame.maxY - size.height - 12,
                              width: size.width, height: size.height), display: true)
        panel.invalidateShadow()
    }
}

private struct CardContent: View {
    let event: GuardEvent
    let preview: Bool
    let expanded: Bool
    let toggle: () -> Void
    let close: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 11) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 18, weight: .medium))
                    .frame(width: 34, height: 34)
                    .background(.primary.opacity(0.055), in: RoundedRectangle(cornerRadius: 10))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 5) {
                        Text(verbatim: "\(event.path.service.signalTitle) · IPv\(event.path.family)")
                        if let old = event.previous, old.country != event.current.country {
                            Text(verbatim: old.country)
                            Image(systemName: "arrow.right").font(.caption).foregroundStyle(.secondary)
                        } else {
                            Text(event.previous == nil ? "为" : "仍为").foregroundStyle(.secondary)
                        }
                        Text(verbatim: event.current.country).foregroundStyle(Color.red)
                    }
                    .font(.system(size: 16, weight: .semibold))
                    .accessibilityElement(children: .combine)
                    if !event.closed.isEmpty {
                        Text("已关闭 " + event.closed.joined(separator: "、"))
                    } else if event.failed.isEmpty {
                        Text("未发现运行中的受保护应用")
                    }
                    if !event.failed.isEmpty {
                        Text(event.failed.joined(separator: "、") + " 未能退出")
                    }
                }
                .font(.system(size: 13))
                .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                Button(action: close) {
                    Image(systemName: "xmark").font(.system(size: 9, weight: .bold))
                        .foregroundStyle(.secondary).frame(width: 22, height: 22)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain).accessibilityLabel("关闭提示").help("关闭提示")
            }
            HStack {
                Button(action: toggle) {
                    HStack(spacing: 5) {
                        Text(expanded ? "收起详情" : "查看检测详情")
                        Image(systemName: expanded ? "chevron.up" : "chevron.right")
                            .font(.system(size: 9, weight: .semibold))
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                Spacer()
                if preview { Text("示例预览") }
            }
            .padding(.leading, 45)
            .font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
            if expanded {
                Divider()
                Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 7) {
                    detail("检测结果", (event.path.service == .google ? "Google X-Country" : "Cloudflare loc") + " · " + event.current.country)
                    if let previousIP = event.previous?.ip {
                        detail("上次出口 IP", previousIP, address: true)
                    }
                    if let ip = event.current.ip {
                        detail("本次出口 IP", ip, address: true)
                    }
                    if let destination = event.current.destinationIP {
                        detail("服务器目标 IP", destination, address: true)
                    }
                    detail("检测路径", "\(event.path.route.title) · IPv\(event.path.family)")
                    if let time = event.time {
                        detail("检测时间", time.formatted(.dateTime.year().month().day().hour().minute().second().locale(Locale(identifier: "zh_CN"))))
                    }
                }
            }
        }
        .padding(16)
        .frame(width: 366, alignment: .leading)
        .fixedSize(horizontal: false, vertical: true)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 17, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 17, style: .continuous)
                .strokeBorder(.primary.opacity(0.12), lineWidth: 1)
        }
    }

    private func detail(_ label: String, _ value: String, address: Bool = false) -> some View {
        GridRow {
            Text(verbatim: label).font(.system(size: 11)).foregroundStyle(.secondary)
            Text(verbatim: value)
                .font(.system(size: 11.5, design: address ? .monospaced : .default))
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
