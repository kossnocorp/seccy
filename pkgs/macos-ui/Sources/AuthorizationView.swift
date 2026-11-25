import SwiftUI
import UniformTypeIdentifiers
import Darwin
import LocalAuthentication
import LocalAuthenticationEmbeddedUI

/// Shared semantic colors for the authorization prompt, popovers and gallery.
enum UIPalette {
    static let secondary = Color.secondary
    static let mutedIcon = Color(nsColor: .secondaryLabelColor)
    static let connector = mutedIcon.opacity(0.6)
    static let windowSurface = Color(nsColor: .windowBackgroundColor)
    static let barTint = Color.primary.opacity(0.035)
    static let secondaryIconOpacity = 0.62
    static let transparentWindow = NSColor.clear
    static let clear = Color.clear
    static let chipFill = Color.primary.opacity(0.05)
    static let chipOutline = Color.primary.opacity(0.14)
    static let badgeOutline = secondary.opacity(0.25)
    static let accent = Color.accentColor
    static let selectionFill = accent.opacity(0.1)
    static let success = Color.green
    static let warning = Color.orange
    static let error = Color.red
}

struct KeyInfo: Codable {
    var name: String
    var fingerprint: String
    var algorithm: String?
    var publicKeyPath: String?
}

struct PromptPresentation: Codable {
    let version: Int
    let title: String
    var rows: [[PromptNode]]
}

struct PromptProcessRef: Codable {
    let pid: Int32
    let label: String
}

struct RepositoryLocation: Codable {
    struct Origin: Codable {
        let provider: String
        let slug: String
        var page: URL? {
            let hosts = ["github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"]
            let parts = slug.components(separatedBy: "/")
            let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
            guard let host = hosts[provider], parts.count >= 2,
                  provider == "gitlab" || parts.count == 2,
                  parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && $0.unicodeScalars.allSatisfy(allowed.contains) })
            else { return nil }
            return URL(string: "https://\(host)/\(slug)")
        }
    }
    let directory: String
    let origin: Origin
}

enum PromptNode: Codable {
    case text(String), processes([PromptProcessRef]), directory(String), keys([String]), action(String), secrets([String])
    case repository(RepositoryLocation)
    var isLocation: Bool {
        switch self { case .directory, .repository: return true; default: return false }
    }
    private enum CodingKeys: CodingKey { case kind, value }
    private enum Kind: String, Codable { case text, processes, directory, repository, keys, action, secrets }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(Kind.self, forKey: .kind) {
        case .text: self = .text(try c.decode(String.self, forKey: .value))
        case .processes: self = .processes(try c.decode([PromptProcessRef].self, forKey: .value))
        case .directory: self = .directory(try c.decode(String.self, forKey: .value))
        case .repository: self = .repository(try c.decode(RepositoryLocation.self, forKey: .value))
        case .keys: self = .keys(try c.decode([String].self, forKey: .value))
        case .action: self = .action(try c.decode(String.self, forKey: .value))
        case .secrets: self = .secrets(try c.decode([String].self, forKey: .value))
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        func put<T: Encodable>(_ kind: Kind, _ value: T) throws {
            try c.encode(kind, forKey: .kind)
            try c.encode(value, forKey: .value)
        }
        switch self {
        case .text(let v): try put(.text, v)
        case .processes(let v): try put(.processes, v)
        case .directory(let v): try put(.directory, v)
        case .repository(let v): try put(.repository, v)
        case .keys(let v): try put(.keys, v)
        case .action(let v): try put(.action, v)
        case .secrets(let v): try put(.secrets, v)
        }
    }
}

struct AuthorizationRequest: Codable {
    var presentation: PromptPresentation? = nil
    var content: AuthorizationContent
    var notification: NotificationContent?
    let pidLabel: String
    var key: String
    let fingerprint: String
    let executable: String
    let pid: Int32
    var processes: [ProcessPresentation]? = nil
    var header: AuthorizationHeader? = nil
    var appPid: Int32? = nil
    var workingDirectory: String? = nil
    var originalDirectory: String? = nil
    var previewCopy: GalleryCopy? = nil
    var diagnostics: String? = nil
    var isReplay: Bool? = nil
    var keyInfo: [KeyInfo]? = nil
    var ancestryInterruption: String? = nil

    var title: String { content.title }
    var body: String { content.body }

    static func abbreviatedDirectory(_ path: String, home: String = NSHomeDirectory()) -> String {
        if path == home { return "~" }
        if path.hasPrefix(home + "/") { return "~/" + path.dropFirst(home.count + 1) }
        return path
    }

    func preview(key: String, directory: String) -> AuthorizationRequest {
        var request = self
        request.key = key
        if previewCopy != nil {
            request.keyInfo = [KeyInfo(name: key, fingerprint: fingerprint,
                algorithm: "ecdsa-sha2-nistp256", publicKeyPath: "~/.local/state/seccy/keys/\(key).pub")]
        }
        request.workingDirectory = directory.isEmpty ? nil : (directory as NSString).expandingTildeInPath
        if var model = presentation, previewCopy != nil {
            model.rows = model.rows.compactMap { row in
                if directory.isEmpty, row.contains(where: \.isLocation) { return nil }
                return row.map { node in
                    switch node {
                    case .keys: return .keys([key])
                    case .directory: return .directory(request.workingDirectory ?? directory)
                    case .repository(let location):
                        if location.directory == directory { return node }
                        return .directory(request.workingDirectory ?? directory)
                    default: return node
                    }
                }
            }
            request.presentation = model
        }
        guard let template = previewCopy else { return request }
        func substitute(_ text: String) -> String {
            text.replacingOccurrences(of: "\u{e000}seccy-key\u{e001}", with: Self.display(key))
        }
        request.content = AuthorizationContent(title: substitute(template.content.title),
                                               body: substitute(template.content.body),
                                               warning: template.content.warning)
        request.notification = NotificationContent(title: substitute(template.notification.title),
                                                   body: substitute(template.notification.body))
        request.header = AuthorizationHeader(requestTitle: template.header.requestTitle, keyAction: template.header.keyAction, title: substitute(template.header.title),
                                             target: template.header.target,
                                             action: template.header.action,
                                             permission: template.header.permission.map {
                                                 PermissionPart(kind: $0.kind, value: substitute($0.value))
                                             })
        return request
    }

    // Literal Text, not Markdown: process names and remote values are untrusted.
    static func display(_ value: String, limit: Int = 8192) -> String {
        String(value.unicodeScalars.map { scalar in
            if CharacterSet.controlCharacters.contains(scalar) || (0x2028...0x202e).contains(scalar.value) || (0x2066...0x2069).contains(scalar.value) {
                return String(format: "\\u{%x}", scalar.value)
            }
            return String(scalar)
        }.joined().prefix(limit))
    }
}

// JSON preserves argument boundaries and escapes embedded newlines. Also escape
// directional controls, but retain formatting and every byte of diagnostic text.
private struct DiagnosticText: View {
    let value: String

    var body: some View {
        Text(verbatim: value.components(separatedBy: "\n").map {
            AuthorizationRequest.display($0, limit: Int.max)
        }.joined(separator: "\n"))
            .font(.system(.caption, design: .monospaced))
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .textSelection(.enabled)
    }
}

struct ProcessPresentation: Codable, Identifiable {
    var limited: Bool? = nil
    let pid: Int32
    let pidLabel: String
    let name: String
    let executable: String?
    let startSeconds: UInt64
    let startMicroseconds: UInt64
    let bundlePaths: [String]
    var diagnostics: String? = nil
    var capturedIconPNG: Data? = nil
    var isReplay: Bool? = nil

    var id: String { "\(pid):\(startSeconds):\(startMicroseconds)" }
    var isGit: Bool { executable.map { URL(fileURLWithPath: $0).lastPathComponent == "git" } ?? false }
}

enum ProcessIconResolver {
    static var fallback: NSImage { NSWorkspace.shared.icon(for: .unixExecutable) }

    // PID reuse must not attach another application's icon to this snapshot.
    private static func matches(_ process: ProcessPresentation) -> Bool {
        guard process.pid > 0, process.startSeconds > 0 else { return false }
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(process.pid, PROC_PIDTBSDINFO, 0, &info, size) == size,
              info.pbi_start_tvsec == process.startSeconds,
              info.pbi_start_tvusec == process.startMicroseconds else { return false }
        // PROC_PIDPATHINFO_MAXSIZE is a compound C macro Swift cannot import.
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath(process.pid, &path, UInt32(path.count)) > 0 else { return false }
        return String(cString: path) == process.executable
    }

    static func resolve(_ process: ProcessPresentation) -> NSImage {
        if process.isReplay == true {
            return process.capturedIconPNG.flatMap(NSImage.init(data:)) ?? fallback
        }
        if matches(process),
           let icon = NSRunningApplication(processIdentifier: process.pid)?.icon,
           matches(process) {
            return icon
        }
        for path in process.bundlePaths where FileManager.default.fileExists(atPath: path) {
            return NSWorkspace.shared.icon(forFile: path)
        }
        return fileIcon(process.executable)
    }

    static func fileIcon(_ path: String?) -> NSImage {
        guard let path = path, FileManager.default.fileExists(atPath: path) else { return fallback }
        return NSWorkspace.shared.icon(forFile: path)
    }
}

enum FinderTarget: Equatable {
    case directory(URL), file(URL)

    static func resolve(_ path: String, directoryOnly: Bool) -> Self? {
        let full = (path as NSString).expandingTildeInPath
        guard full.hasPrefix("/") else { return nil }
        let url = URL(fileURLWithPath: full)
        var dir: ObjCBool = false
        if FileManager.default.fileExists(atPath: full, isDirectory: &dir) {
            if dir.boolValue { return .directory(url) }
            return directoryOnly ? nil : .file(url)
        }
        let parent = url.deletingLastPathComponent()
        guard !directoryOnly, FileManager.default.fileExists(atPath: parent.path, isDirectory: &dir),
              dir.boolValue else { return nil }
        return .directory(parent)
    }

    func open() {
        switch self {
        case .directory(let url): NSWorkspace.shared.open(url)
        case .file(let url):
            let parent = url.deletingLastPathComponent()
            if !NSWorkspace.shared.selectFile(url.path, inFileViewerRootedAtPath: parent.path) {
                NSWorkspace.shared.open(parent)
            }
        }
    }
}

private struct FinderPath: View {
    let path: String
    var label: String? = nil
    var directory = false
    var dimmed = false
    @State private var hovered = false

    var body: some View {
        let full = (path as NSString).expandingTildeInPath
        let target = FinderTarget.resolve(full, directoryOnly: directory)
        let text = Text(verbatim: AuthorizationRequest.display(label ?? path, limit: Int.max))
            .lineLimit(1).truncationMode(.middle)
        let glass = Image(systemName: "magnifyingglass").font(.caption).frame(width: 14).accessibilityHidden(true)
        Button { FinderTarget.resolve(full, directoryOnly: directory)?.open() } label: {
            HStack(spacing: 4) {
                if directory {
                    Image(nsImage: NSWorkspace.shared.icon(for: .folder)).resizable().frame(width: 16, height: 16)
                        .accessibilityHidden(true)
                }
                text
                if !dimmed || hovered { glass.fixedSize() }
            }
            .modifier(InlineChipAppearance(hovered: hovered))
            .background {
                if hovered {
                    RoundedRectangle(cornerRadius: 5, style: .continuous).fill(.ultraThinMaterial)
                }
            }
            .onHover { hovered = $0 && target != nil }
        }.buttonStyle(.plain).disabled(target == nil)
            .help(Text(verbatim: AuthorizationRequest.display(full, limit: Int.max)))
            .accessibilityLabel(Text(verbatim: AuthorizationRequest.display(full, limit: Int.max)))
            .accessibilityHint(Copy.text("ui-path-show-in-finder"))
            // Float the material-backed reveal over adjacent content without
            // taking width from the resting path or moving the next link.
            .padding(.trailing, dimmed && hovered ? -18 : 0)
            .zIndex(dimmed && hovered ? 1 : 0)
    }
}

// Resolve once per request identity, rather than during SwiftUI body updates.
private struct ProcessIdentityView: View {
    let process: ProcessPresentation
    var prominent = false
    @State private var icon: NSImage?
    @State private var artworkAdjustment = EdgeInsets()

    // App icons often have transparent canvas and a faint shadow outside the
    // artwork. Align the artwork, rather than the canvas, with the JSON block.
    private static func alignmentAdjustment(of image: NSImage, side: CGFloat) -> EdgeInsets {
        let pixels = Int(side * 2)
        var rect = CGRect(origin: .zero, size: image.size)
        guard let cg = image.cgImage(forProposedRect: &rect, context: nil, hints: nil),
              let ctx = CGContext(data: nil, width: pixels, height: pixels, bitsPerComponent: 8,
                                  bytesPerRow: pixels * 4, space: CGColorSpaceCreateDeviceRGB(),
                                  bitmapInfo: CGBitmapInfo.byteOrder32Big.rawValue | CGImageAlphaInfo.premultipliedLast.rawValue),
               let data = ctx.data else { return EdgeInsets() }
        let scale = CGFloat(pixels) / max(image.size.width, image.size.height, 1)
        let size = CGSize(width: image.size.width * scale, height: image.size.height * scale)
        ctx.clear(CGRect(x: 0, y: 0, width: pixels, height: pixels))
        ctx.draw(cg, in: CGRect(x: (CGFloat(pixels) - size.width) / 2,
                                y: (CGFloat(pixels) - size.height) / 2,
                                width: size.width, height: size.height))
        let rgba = data.assumingMemoryBound(to: UInt8.self)
        var left = pixels, top = pixels, right = -1, bottom = -1
        for y in 0..<pixels {
            for x in 0..<pixels where rgba[y * ctx.bytesPerRow + x * 4 + 3] >= 96 {
                left = min(left, x)
                right = max(right, x)
                top = min(top, y)
                bottom = y
            }
        }
        guard right >= left else { return EdgeInsets() }
        return EdgeInsets(top: -CGFloat(top) / 2, leading: -CGFloat(left) / 2,
                          bottom: -CGFloat(pixels - 1 - bottom) / 2,
                          trailing: -CGFloat(pixels - 1 - right) / 2)
    }

    var body: some View {
        HStack(alignment: .center, spacing: prominent ? PopoverLayout.blockPadding : 12) {
            Image(nsImage: icon ?? ProcessIconResolver.fallback)
                .resizable().scaledToFit()
                .frame(width: prominent ? 48 : 28, height: prominent ? 48 : 28)
                .padding(artworkAdjustment)
                .opacity(UIPalette.secondaryIconOpacity)
                .allowsHitTesting(false)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(verbatim: AuthorizationRequest.display(process.name))
                        .font(prominent ? .headline : .body).fontWeight(.semibold)
                        .lineLimit(1).layoutPriority(1)
                        .allowsHitTesting(prominent)
                    if let path = process.executable {
                        FinderPath(path: path, dimmed: true)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(UIPalette.secondary)
                    }
                }
                Text(process.pidLabel).font(.caption).foregroundStyle(UIPalette.secondary)
                    .allowsHitTesting(prominent)
                if process.limited == true {
                    Text(Copy.text("ui-chain-limited")).font(.caption).foregroundStyle(UIPalette.secondary)
                        .allowsHitTesting(prominent)
                }
            }
            Spacer(minLength: 0)
        }
        .task(id: process.id) {
            let resolved = ProcessIconResolver.resolve(process)
            artworkAdjustment = prominent ? Self.alignmentAdjustment(of: resolved, side: 48) : EdgeInsets()
            icon = resolved
        }
    }
}

private struct InlineChipAppearance: ViewModifier {
    let hovered: Bool
    var presented = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: 5, style: .continuous)
        let animation: Animation? = reduceMotion ? nil : .easeInOut(duration: 0.16)
        return content.padding(.horizontal, 4).padding(.vertical, 2)
            .background(shape.fill(hovered ? UIPalette.chipFill : UIPalette.clear)
                .animation(animation, value: hovered))
            .overlay(shape.strokeBorder(hovered || presented ? UIPalette.chipOutline : UIPalette.clear)
                .animation(animation, value: hovered || presented))
            .contentShape(Rectangle())
    }
}

private struct InlineInfoButton<Label: View, Panel: View>: View {
    let tooltip: String
    @ViewBuilder var label: () -> Label
    @ViewBuilder var panel: () -> Panel
    @State private var hovered = false
    @State private var presented = false

    var body: some View {
        Button { presented.toggle() } label: {
            label().modifier(InlineChipAppearance(hovered: hovered, presented: presented))
        }
        .buttonStyle(.plain)
        .onHover { hovered = $0 }
        .help(Text(verbatim: tooltip))
        .background(WindowDragExclusion())
        .popover(isPresented: $presented) { panel().lineLimit(nil) }
    }
}

enum AuthorizationState: String, CaseIterable, Identifiable {
    case ready, authenticating, success, failure, unavailable, cancelled, warning
    var label: String { Copy.text("ui-state-" + rawValue) }
    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .success: return "checkmark.circle.fill"
        case .failure, .unavailable, .warning: return "exclamationmark.triangle.fill"
        case .cancelled: return "xmark.circle"
        default: return "touchid"
        }
    }
    var color: Color {
        switch self {
        case .success: return UIPalette.success
        case .failure, .unavailable, .warning: return UIPalette.warning
        default: return UIPalette.accent
        }
    }
    var message: String { Copy.text("ui-status-" + rawValue) }
}

// Keep SwiftUI's sizing passes outside the animated native control. The host
// has a constant size; its child and constraints live for the entire attempt.
final class FingerprintHostView: NSView {
    let authenticationView: LAAuthenticationView
    var appeared: () -> Void = {}

    func reportAttachment() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.window != nil, self.superview != nil else { return }
            self.layoutSubtreeIfNeeded()
            self.appeared()
        }
    }

    init(context: LAContext) {
        authenticationView = LAAuthenticationView(context: context, controlSize: .small)
        super.init(frame: NSRect(x: 0, y: 0, width: 32, height: 32))
        UITrace.event("fingerprint.created", ["host": UITrace.id(self), "native": UITrace.id(authenticationView), "context": UITrace.id(context)])
        let nativeSize = authenticationView.fittingSize
        // LocalAuthentication validates the on-screen dimensions. Give it a
        // valid frame before attachment, and never scale the native control.
        authenticationView.frame = NSRect(origin: .zero, size: nativeSize)
        authenticationView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(authenticationView)
        NSLayoutConstraint.activate([
            authenticationView.centerXAnchor.constraint(equalTo: centerXAnchor),
            authenticationView.centerYAnchor.constraint(equalTo: centerYAnchor),
            authenticationView.widthAnchor.constraint(equalToConstant: nativeSize.width),
            authenticationView.heightAnchor.constraint(equalToConstant: nativeSize.height),
        ])
    }

    override func layout() {
        super.layout()
        UITrace.event("fingerprint.layout", ["host": UITrace.id(self), "frame": NSStringFromRect(frame), "native_frame": NSStringFromRect(authenticationView.frame)])
    }
    override func setFrameSize(_ newSize: NSSize) {
        UITrace.event("fingerprint.frame", ["host": UITrace.id(self), "old": NSStringFromSize(frame.size), "new": NSStringFromSize(newSize)])
        super.setFrameSize(newSize)
    }
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        UITrace.event("fingerprint.window", ["host": UITrace.id(self), "window": UITrace.id(window)])
        reportAttachment()
    }
    override func viewDidMoveToSuperview() {
        super.viewDidMoveToSuperview()
        UITrace.event("fingerprint.superview", ["host": UITrace.id(self), "superview": UITrace.id(superview)])
    }
    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        UITrace.event("fingerprint.appearance", ["host": UITrace.id(self), "appearance": effectiveAppearance.name.rawValue])
    }
    deinit { UITrace.event("fingerprint.destroyed", ["host": UITrace.id(self)]) }
    required init?(coder: NSCoder) { nil }
    override var intrinsicContentSize: NSSize { NSSize(width: 32, height: 32) }
}

struct FingerprintView: NSViewRepresentable {
    let context: LAContext
    var appeared: () -> Void = {}
    func makeNSView(context: Context) -> FingerprintHostView {
        let view = FingerprintHostView(context: self.context)
        view.appeared = appeared
        return view
    }
    func updateNSView(_ view: FingerprintHostView, context: Context) {
        UITrace.event("fingerprint.update", ["host": UITrace.id(view), "context": UITrace.id(self.context)])
        view.appeared = appeared
        view.reportAttachment()
    }
    static func dismantleNSView(_ view: FingerprintHostView, coordinator: ()) {
        UITrace.event("fingerprint.dismantle", ["host": UITrace.id(view)])
    }
}

private enum PopoverLayout {
    static let inset: CGFloat = 16
    static let blockPadding: CGFloat = 8
    static let listItemInset: CGFloat = 8
    static let listEdgeInset = inset - listItemInset
    static let maxProcessBodyHeight: CGFloat = 320
}

private extension View {
    func popoverBlock() -> some View {
        frame(maxWidth: .infinity, alignment: .leading)
            .padding(PopoverLayout.blockPadding)
            .background { GroupBox { Color.clear }.accessibilityHidden(true) }
    }
}

private struct DetailHeight: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}

private struct ProcessPanel: View {
    let processes: [ProcessPresentation]
    let interruption: String?
    @State private var selection: ProcessPresentation?
    @State private var direct: Bool
    @State private var highlighted: String?
    @State private var detailHeight: CGFloat = 64
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(_ processes: [ProcessPresentation], interruption: String?, initial: ProcessPresentation? = nil) {
        self.processes = processes
        self.interruption = interruption
        _selection = State(initialValue: initial)
        _direct = State(initialValue: initial != nil)
        _highlighted = State(initialValue: initial?.id)
    }

    private var processList: some View {
        List {
            ForEach(processes) { process in
                let row = ZStack {
                    Button {
                        highlighted = process.id
                        direct = false
                        withAnimation(reduceMotion ? nil : .easeOut(duration: 0.18)) { selection = process }
                    } label: {
                        Color.clear.contentShape(Rectangle())
                    }.buttonStyle(.plain)
                        .accessibilityLabel(Text(verbatim: "\(AuthorizationRequest.display(process.name)), \(process.pidLabel)"))
                    HStack(spacing: 8) {
                        ProcessIdentityView(process: process)
                        Image(systemName: "chevron.forward")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(UIPalette.secondary)
                            .accessibilityHidden(true)
                            .allowsHitTesting(false)
                    }
                    // The plain macOS list already insets each cell.
                    .padding(.horizontal, PopoverLayout.listEdgeInset)
                }
                .frame(height: rowHeight(process))
                .overlay(alignment: .bottom) {
                    if process.id != processes.last?.id { Divider().allowsHitTesting(false) }
                }
                .listRowInsets(EdgeInsets())
                .listRowBackground(highlighted == process.id ? UIPalette.selectionFill : UIPalette.clear)
                .id(process.id)
                if #available(macOS 13, *) {
                    row.listRowSeparator(.hidden)
                } else {
                    row
                }
            }
        }.listStyle(.plain)
        .environment(\.defaultMinListRowHeight, 0)
        .frame(height: min(PopoverLayout.maxProcessBodyHeight, processes.reduce(0) { $0 + rowHeight($1) }))
    }

    private func rowHeight(_ process: ProcessPresentation) -> CGFloat {
        (process.limited == true ? 40 : 26) + 2 * PopoverLayout.listItemInset
    }

    private func stepButton(to index: Int, symbol: String, label: String) -> some View {
        Button {
            guard processes.indices.contains(index) else { return }
            selection = processes[index]
            highlighted = processes[index].id
        } label: { Image(systemName: symbol) }
        .disabled(!processes.indices.contains(index))
        .help(Copy.text(label))
        .accessibilityLabel(Copy.text(label))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                if selection != nil {
                    Button {
                        withAnimation(reduceMotion ? nil : .easeOut(duration: 0.18)) { selection = nil }
                    } label: { Image(systemName: direct ? "list.bullet" : "chevron.backward").frame(width: 16) }
                    .help(Copy.text(direct ? "ui-chain-all" : "ui-chain-back"))
                    .accessibilityLabel(Copy.text(direct ? "ui-chain-all" : "ui-chain-back"))
                }
                Text(Copy.text("ui-process-chain")).font(.headline)
                Spacer()
                if let selection, let index = processes.firstIndex(where: { $0.id == selection.id }) {
                    HStack(spacing: 4) {
                        stepButton(to: index - 1, symbol: "chevron.left", label: "ui-chain-previous")
                        stepButton(to: index + 1, symbol: "chevron.right", label: "ui-chain-next")
                    }
                }
            }
            .padding(.horizontal, PopoverLayout.inset)
            .frame(maxWidth: .infinity, minHeight: 42, alignment: .leading)
            .background(UIPalette.barTint)
            Divider()
            ZStack(alignment: .topLeading) {
                // Keep the list mounted so Back preserves its scroll position.
                ScrollViewReader { proxy in
                    VStack(alignment: .leading, spacing: 8) {
                        if let interruption {
                            Text(verbatim: interruption).font(.caption).textSelection(.enabled)
                                .padding(.horizontal, PopoverLayout.inset)
                        }
                        if #available(macOS 14, *) {
                            processList.scrollContentBackground(.hidden).contentMargins(0, for: .scrollContent)
                        } else if #available(macOS 13, *) {
                            processList.scrollContentBackground(.hidden)
                        } else {
                            processList
                        }
                    }
                    .padding(.vertical, PopoverLayout.listEdgeInset)
                    .onAppear { if let highlighted { proxy.scrollTo(highlighted) } }
                }
                .opacity(selection == nil ? 1 : 0).allowsHitTesting(selection == nil)
                .accessibilityHidden(selection != nil)
                .frame(height: selection == nil ? nil : 0)
                if let process = selection {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 12) {
                            ProcessIdentityView(process: process, prominent: true)
                                .popoverBlock()
                            if let diagnostics = process.diagnostics {
                                DiagnosticText(value: diagnostics).popoverBlock()
                            }
                        }.textSelection(.enabled)
                        .padding(PopoverLayout.inset)
                        .fixedSize(horizontal: false, vertical: true)
                        .background(GeometryReader { size in
                            Color.clear.preference(key: DetailHeight.self, value: size.size.height)
                        })
                    }
                    .onPreferenceChange(DetailHeight.self) { if $0 > 0 { detailHeight = ceil($0) } }
                    .frame(height: min(detailHeight, PopoverLayout.maxProcessBodyHeight))
                    .transition(.move(edge: .trailing))
                }
            }.clipped()
        }.multilineTextAlignment(.leading).frame(width: 390).fixedSize(horizontal: false, vertical: true)
    }
}

private struct ProcessChipLabel: View {
    let process: ProcessPresentation
    var label: String? = nil
    @State private var icon: NSImage?
    var body: some View {
        HStack(spacing: 3) {
            Image(nsImage: icon ?? ProcessIconResolver.fallback)
                .resizable().frame(width: 16, height: 16).accessibilityHidden(true)
            Text(verbatim: label.map { AuthorizationRequest.display($0) } ?? process.chipName).bold().lineLimit(1).truncationMode(.middle)
        }.task(id: process.id) { icon = ProcessIconResolver.resolve(process) }
    }
}

extension ProcessPresentation {
    var chipName: String {
        let label = AuthorizationRequest.display(name)
        guard isGit, let diagnostics,
              let object = try? JSONSerialization.jsonObject(with: Data(diagnostics.utf8)) as? [String: Any],
              let details = object["details"] as? [String: Any],
              let command = details["command"] as? [String: Any],
              let verb = command["subcommand"] as? String else { return label }
        return label + " " + AuthorizationRequest.display(verb)
    }
}

private struct SecretWidth: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = nextValue() }
}

private struct SecretNamesButton: View {
    let names: [String]
    @State private var idealWidth: CGFloat = 0

    var body: some View {
        let preview = names.prefix(3).map { AuthorizationRequest.display($0, limit: Int.max) }.joined(separator: ", ")
        let title = Copy.text("ui-secret-list")
        InlineInfoButton(tooltip: title) {
            Text(verbatim: preview).lineLimit(1).hidden()
                .overlay(GeometryReader { space in
                    Text(verbatim: preview).fixedSize()
                        .background(GeometryReader { g in
                            Color.clear.preference(key: SecretWidth.self, value: g.size.width)
                        })
                        .frame(width: space.size.width, alignment: .leading).clipped()
                        .mask(HStack(spacing: 0) {
                            Color.primary
                            if names.count > 3 || idealWidth > space.size.width + 0.5 {
                                LinearGradient(colors: [.primary, .clear], startPoint: .leading, endPoint: .trailing)
                                    .frame(width: min(24, space.size.width / 2))
                            }
                        })
                })
                .onPreferenceChange(SecretWidth.self) { idealWidth = $0 }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(title): \(names.count)")
        } panel: {
            VStack(alignment: .leading, spacing: 12) {
                Text("\(title) (\(names.count))").font(.headline)
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(names.indices, id: \.self) { i in
                            Text(verbatim: AuthorizationRequest.display(names[i], limit: Int.max))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                }
            }.lineLimit(nil).padding(PopoverLayout.inset).frame(width: 340, height: 220)
        }
    }
}

struct AuthorizationView: View {
    let request: AuthorizationRequest
    let state: AuthorizationState
    var context: LAContext? = nil
    var fingerprintAppeared: (LAContext) -> Void = { _ in }
    var retry: () -> Void = {}
    var cancel: () -> Void = {}
    @State private var appIcon: NSImage?
    @State private var originIcon: NSImage?
    @State private var repositoryHovered = false

    private var warning: Bool { request.content.warning }
    private var requester: ProcessPresentation {
        request.processes?.first(where: { $0.pid == request.pid }) ??
            ProcessPresentation(pid: request.pid, pidLabel: request.pidLabel,
                                name: URL(fileURLWithPath: request.executable).lastPathComponent,
                                executable: request.executable, startSeconds: 0,
                                startMicroseconds: 0, bundlePaths: [])
    }
    private var application: ProcessPresentation {
        request.processes?.first(where: { $0.pid == request.appPid }) ?? requester
    }
    private var origin: ProcessPresentation? {
        guard request.ancestryInterruption == nil,
              let first = request.processes?.last(where: { $0.pid != 1 }),
              first.id != application.id else { return nil }
        return first
    }

    private static let inlineKeyIcon = Copy.icon("key", size: 20)

    private func keyButton(_ label: String) -> some View {
        InlineInfoButton(tooltip: request.fingerprint) {
            HStack(spacing: 4) {
                Image(nsImage: Self.inlineKeyIcon).accessibilityHidden(true)
                Text(verbatim: label).bold()
            }
        } panel: {
            let entries = request.keyInfo ?? [KeyInfo(name: request.key, fingerprint: request.fingerprint)]
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(entries.indices, id: \.self) { index in
                        let entry = entries[index]
                        if index > 0 { Divider() }
                        HStack(spacing: PopoverLayout.blockPadding) {
                            Image(nsImage: Self.inlineKeyIcon).accessibilityHidden(true)
                            Text(verbatim: AuthorizationRequest.display(entry.name)).font(.headline)
                        }.popoverBlock()
                        VStack(alignment: .leading, spacing: 12) {
                            keyField("ui-key-fingerprint", entry.fingerprint)
                            if let algorithm = entry.algorithm { keyField("ui-key-algorithm", algorithm) }
                            if let path = entry.publicKeyPath { publicKeyFileField(path) }
                        }.popoverBlock()
                    }
                }.padding(PopoverLayout.inset).frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(width: 340, height: entries.count > 1 ? 300 : 247)
            .multilineTextAlignment(.leading)
        }
    }

    private func publicKeyFileField(_ path: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(Copy.text("ui-key-public-file")).font(.caption).foregroundStyle(UIPalette.secondary)
            FinderPath(path: path).font(.system(.body, design: .monospaced))
        }
    }

    private func keyField(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(Copy.text(label)).font(.caption).foregroundStyle(UIPalette.secondary)
            Text(verbatim: AuthorizationRequest.display(value)).font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
        }
    }

    private var chain: [ProcessPresentation] {
        [requester] + (request.processes ?? []).filter { $0.pid != request.pid }
    }

    private func processChip(_ process: ProcessPresentation, label: String? = nil) -> some View {
        InlineInfoButton(tooltip: AuthorizationRequest.display(process.executable ?? process.name)) {
            ProcessChipLabel(process: process, label: label)
        } panel: {
            ProcessPanel(chain, interruption: request.ancestryInterruption, initial: process)
        }
    }

    private var chainChevron: some View {
        Image(systemName: "chevron.left")
            .font(.caption.weight(.semibold))
            .foregroundStyle(UIPalette.connector)
            .accessibilityHidden(true)
    }

    private func chainRow(_ refs: [PromptProcessRef]? = nil) -> some View {
        let observed = chain
        let processes = refs?.compactMap { ref in observed.first { $0.pid == ref.pid } } ?? observed
        return HStack(spacing: 2) {
            ForEach(processes.prefix(3)) { process in
                if process.id != processes.first?.id { chainChevron }
                processChip(process, label: refs?.first { $0.pid == process.pid }?.label)
            }
            chainChevron
            InlineInfoButton(tooltip: Copy.text("ui-chain-all")) {
                Text(verbatim: "⋯").accessibilityLabel(Copy.text("ui-chain-all"))
            } panel: { ProcessPanel(processes, interruption: request.ancestryInterruption) }
            .fixedSize()
        }
    }

    private var actionLabel: String {
        if let value = request.header?.keyAction, !value.isEmpty { return value }
        // Older captures predate the semantic action label. Use the recorded
        // request rather than inferring authorization scope from the hero icon.
        if let raw = request.diagnostics,
           let object = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
           let signing = object["signing"] as? [String: Any] {
            let decoded = signing["decoded"] as? [String: Any]
            if decoded?["kind"] as? String == "ssh_authentication" { return Copy.text("ui-key-action-ssh") }
            return Copy.text(decoded?["namespace"] as? String == "git" ? "ui-key-action-sign-git" : "ui-key-action-sign")
        }
        return Copy.text("ui-key-action-use")
    }

    private func directoryButton(_ directory: String) -> some View {
        FinderPath(path: request.originalDirectory ?? directory,
                   label: AuthorizationRequest.abbreviatedDirectory(directory), directory: true, dimmed: true)
            .background(WindowDragExclusion())
    }

    private func actionButton(_ label: String) -> some View {
        InlineInfoButton(tooltip: Copy.text("ui-request-details")) {
            Text(verbatim: label).bold()
        } panel: {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: PopoverLayout.blockPadding) {
                        let action = request.header?.action ?? "key"
                        let icon = ["cloud_upload", "cloud_download", "lock_open"].contains(action) ? action : "key"
                        Image(nsImage: Copy.icon(icon, size: 20)).accessibilityHidden(true)
                        Text(verbatim: request.header?.requestTitle ?? request.header?.title ?? request.title)
                            .font(.headline)
                    }.popoverBlock()
                    if let diagnostics = request.diagnostics {
                        DiagnosticText(value: diagnostics).popoverBlock()
                    } else {
                        Text(Copy.text("ui-no-request-snapshot")).foregroundStyle(UIPalette.secondary).popoverBlock()
                    }
                }.textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(PopoverLayout.inset)
            }.frame(width: 420, height: 320).multilineTextAlignment(.leading)
        }
    }

    @ViewBuilder private func render(_ node: PromptNode) -> some View {
        switch node {
        case .text(let text):
            // Fluent owns the word boundaries; give each boundary the same
            // visual width instead of relying on leading/trailing glyph spaces.
            Text(verbatim: text.trimmingCharacters(in: CharacterSet(charactersIn: " ")))
                .fixedSize()
                .padding(.leading, text.hasPrefix(" ") ? PromptPadding.wordGap : 0)
                .padding(.trailing, text.hasSuffix(" ") ? PromptPadding.wordGap : 0)
        case .processes(let refs): chainRow(refs)
        case .directory(let path): directoryButton(path).font(.callout).foregroundStyle(UIPalette.secondary)
        case .repository(let location):
            HStack(spacing: 6) {
                directoryButton(location.directory)
                    // Exclude the chip's trailing hover inset from the separator gap.
                    .padding(.trailing, location.origin.page == nil ? 0 : -4)
                if let page = location.origin.page {
                    Text("·")
                    Link(destination: page) {
                        HStack(spacing: 4) {
                            Image(nsImage: Copy.icon(location.origin.provider, size: 16)).accessibilityHidden(true)
                            Text(verbatim: location.origin.slug).underline(repositoryHovered)
                                .lineLimit(1).truncationMode(.middle)
                        }.contentShape(Rectangle())
                    }.buttonStyle(.plain).onHover { repositoryHovered = $0 }
                        .help(page.absoluteString).background(WindowDragExclusion())
                }
            }.font(.callout).foregroundStyle(UIPalette.secondary)
        case .keys(let names): keyButton(names.map { AuthorizationRequest.display($0) }.joined(separator: ", "))
        case .action(let label): actionButton(label)
        case .secrets(let names): SecretNamesButton(names: names)
        }
    }

    private var permission: some View {
        VStack(spacing: 0) {
            if let model = request.presentation, model.version == 1 {
                ForEach(model.rows.indices, id: \.self) { i in
                    HStack(spacing: 0) {
                        if let location = model.rows[i].first(where: \.isLocation) {
                            render(location) // Old v1 captures also have a "running in" literal.
                        } else {
                            ForEach(model.rows[i].indices, id: \.self) { j in render(model.rows[i][j]) }
                        }
                    }.lineLimit(1)
                        .padding(.top, spacing(before: i, in: model.rows))
                }
            } else {
                // Legacy captures have only formatted copy, never infer secret names from it.
                HStack(spacing: 0) {
                    render(.text(Copy.text("ui-chain-let") + " ")); chainRow()
                }
                HStack(spacing: 0) {
                    render(.text(Copy.text("ui-chain-use") + " ")); keyButton(AuthorizationRequest.display(request.key))
                    render(.text(" " + Copy.text("ui-chain-to") + " ")); actionButton(actionLabel); Text("?")
                }
                .padding(.top, PromptPadding.beforeAction)
                if let directory = request.workingDirectory {
                    directoryButton(directory).font(.callout).foregroundStyle(UIPalette.secondary)
                        .padding(.top, PromptPadding.beforeLocation)
                }
            }
            if request.ancestryInterruption != nil { Text(Copy.text("ui-chain-incomplete")).font(.caption).foregroundStyle(UIPalette.secondary).padding(.top, 8) }
        }
    }

    private func spacing(before index: Int, in rows: [[PromptNode]]) -> CGFloat {
        guard index > 0 else { return 0 }
        if rows[index].contains(where: \.isLocation) { return PromptPadding.beforeLocation }
        return PromptPadding.beforeAction
    }

    private var connectorDots: some View {
        HStack(spacing: 5) {
            ForEach(0..<5) { _ in
                Circle().frame(width: 3, height: 3)
            }
        }
        .frame(width: 35)
        .foregroundStyle(UIPalette.connector)
    }

    private var touchIDLabel: Text {
        let label = Copy.text("ui-touch-id")
        let name = Copy.text("ui-touch-id-name")
        guard let range = label.range(of: name) else { return Text(label) }
        return Text("\(Text(String(label[..<range.lowerBound])))\(Text(name).bold())\(Text(String(label[range.upperBound...])))")
    }

    private var hero: some View {
        HStack(spacing: 8) {
            Image(nsImage: appIcon ?? ProcessIconResolver.fallback)
                .resizable().scaledToFit().frame(width: 72, height: 72)
                .overlay(alignment: .bottomTrailing) {
                    if origin != nil, let image = originIcon {
                        Image(nsImage: image).resizable().scaledToFit().frame(width: 24, height: 24)
                            .padding(4).background(UIPalette.windowSurface, in: Circle())
                            .offset(x: 7, y: 5)
                    }
                }
            HStack(spacing: 8) {
                connectorDots
                Image(nsImage: Copy.icon(["commit", "sell"].contains(request.header?.action ?? "") ? "key" : (request.header?.action ?? "key")))
                    .resizable().scaledToFit().frame(width: 28, height: 28)
                connectorDots
            }
            .foregroundStyle(UIPalette.mutedIcon)
            Image(nsImage: Copy.icon(request.header?.target ?? "key"))
                .resizable().scaledToFit().frame(width: 72, height: 72)
                .overlay(alignment: .bottomTrailing) {
                    if let action = request.header?.action, ["commit", "sell"].contains(action) {
                        Image(nsImage: Copy.icon(action))
                            .resizable().scaledToFit().frame(width: 22, height: 22)
                            .padding(5)
                            .background(UIPalette.windowSurface, in: Circle())
                            .overlay(Circle().strokeBorder(UIPalette.badgeOutline))
                            .offset(x: 8, y: 6)
                    }
                }
        }
        .frame(height: 90)
        .accessibilityHidden(true)
        .task(id: application.id) {
            appIcon = application.isGit ? Copy.icon("git") : ProcessIconResolver.resolve(application)
        }
        .task(id: origin?.id) { originIcon = origin.map(ProcessIconResolver.resolve) }
    }

    private enum PromptPadding {
        static let contentInset: CGFloat = 44
        static let headerIconSpacing: CGFloat = 10
        static let iconToInfoSpacing: CGFloat = 24
        static let infoBoxVertical: CGFloat = beforeLocation + 4
        static let wordGap: CGFloat = 3
        static let beforeAction: CGFloat = 4
        static let beforeLocation: CGFloat = 14
        static let actionBarHorizontal: CGFloat = 20
        static let actionBarVertical: CGFloat = 12
    }

    private var promptContent: some View {
        VStack(spacing: 22) {
            VStack(spacing: PromptPadding.iconToInfoSpacing) {
                VStack(spacing: PromptPadding.headerIconSpacing) {
                    Text(AuthorizationRequest.display(request.presentation?.title ?? request.header?.title ?? request.title))
                        .font(.system(size: 24, weight: .semibold)).multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                    hero
                }
                GroupBox {
                    permission.font(.title3).multilineTextAlignment(.center)
                        .padding(.vertical, PromptPadding.infoBoxVertical)
                        .frame(maxWidth: .infinity)
                }
                .fixedSize(horizontal: false, vertical: true)
            }
            if warning {
                Label(Copy.text("ui-host-warning"), systemImage: "exclamationmark.triangle.fill")
                    .font(.headline).foregroundStyle(UIPalette.warning)
                Text(verbatim: request.body).font(.callout).textSelection(.enabled)
            }
            if state != .ready && state != .authenticating {
                Text(state.message).font(.callout.weight(.medium)).foregroundStyle(state.color)
                    .multilineTextAlignment(.center).accessibilityAddTraits(.updatesFrequently)
            }
        }
        .padding(PromptPadding.contentInset)
    }

    var body: some View {
        let _ = UITrace.event("prompt.body", ["state": state.rawValue, "context": UITrace.id(context)])
        VStack(spacing: 0) {
            promptContent
            Divider()
            HStack(spacing: 8) {
                Button(Copy.text("ui-cancel"), action: cancel).keyboardShortcut(.cancelAction)
                    .background(WindowDragExclusion())
                Spacer()
                touchIDLabel.font(.system(size: 15, weight: .medium))
                ZStack {
                    // LAAuthenticationView may draw nothing until evaluation starts.
                    // Keep it mounted so appearance can start the pending attempt.
                    if let context = context {
                        FingerprintView(context: context, appeared: { fingerprintAppeared(context) })
                            .frame(width: 32, height: 32)
                            .opacity(state == .authenticating ? 1 : 0)
                            .onAppear {
                                UITrace.event("fingerprint.appear", ["context": UITrace.id(context)])
                            }
                            .onDisappear { UITrace.event("fingerprint.disappear", ["context": UITrace.id(context)]) }
                            .id(ObjectIdentifier(context))
                            .accessibilityHidden(state != .authenticating)
                            .accessibilityLabel(Copy.text("ui-touch-id-accessibility"))
                    }
                    if state == .failure || state == .unavailable {
                        Button(action: retry) {
                            Image(systemName: state.symbol).font(.system(size: 24)).foregroundStyle(state.color)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(Copy.text("ui-retry"))
                        .help(Copy.text("ui-retry"))
                    } else if context == nil || state != .authenticating {
                        Image(systemName: state.symbol).font(.system(size: 24)).foregroundStyle(state.color)
                            .accessibilityLabel(state == .ready ? Copy.text("ui-touch-id-accessibility") : state.label)
                    }
                }
                .frame(width: 32, height: 32)
                .background(WindowDragExclusion())
            }
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, PromptPadding.actionBarHorizontal)
            .padding(.vertical, PromptPadding.actionBarVertical)
            .background(UIPalette.barTint)
        }
        .frame(width: 540)
        .fixedSize(horizontal: false, vertical: true)
        .background(UIPalette.windowSurface)
        .background(GeometryReader { geometry in
            AuthorizationWindowLayout(size: geometry.size, cancel: cancel) { _ in }
        })
    }
}

extension AuthorizationRequest {
    static let signing = Copy.fixture("signing")
    static let secrets = Copy.fixture("secrets")
    static let revoked = Copy.fixture("revoked")
    static let long = Copy.fixture("long")
}

// A separate context for a hardware demo; it is never returned to Rust or used
// for keychain access. Each attempt starts fresh, including after cancellation.
final class GalleryAuthentication: ObservableObject {
    @Published private(set) var context = LAContext()
    @Published private(set) var state: AuthorizationState = .ready {
        didSet { UITrace.event("auth.state", ["old": oldValue.rawValue, "new": state.rawValue, "context": UITrace.id(context)]) }
    }
    private var pending = false
    private var attempt = UUID()

    func start() {
        UITrace.event("auth.start", ["old_context": UITrace.id(context)])
        context.invalidate()
        attempt = UUID()
        let fresh = LAContext()
        fresh.touchIDAuthenticationAllowableReuseDuration = 0
        fresh.localizedFallbackTitle = ""
        pending = true
        state = .ready
        context = fresh
        UITrace.event("auth.context", ["context": UITrace.id(context), "attempt": attempt.uuidString])
    }

    func appeared() {
        // Wait until SwiftUI has mounted the LAAuthenticationView before evaluation.
        UITrace.event("auth.appeared", ["pending": String(pending), "attempt": attempt.uuidString])
        guard pending else { return }
        pending = false
        let current = attempt
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.attempt == current else {
                UITrace.event("auth.stale_start", ["attempt": current.uuidString])
                return
            }
            var error: NSError?
            guard self.context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
                UITrace.event("auth.unavailable", ["domain": error?.domain ?? "", "code": String(error?.code ?? 0)])
                self.state = .unavailable
                return
            }
            self.state = .authenticating
            UITrace.event("auth.evaluate", ["context": UITrace.id(self.context), "attempt": current.uuidString])
            self.context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                        localizedReason: Copy.text("gallery-auth-reason")) { [weak self] success, error in
                let failure = error as NSError?
                UITrace.event("auth.reply", ["attempt": current.uuidString, "success": String(success), "domain": failure?.domain ?? "", "code": String(failure?.code ?? 0)])
                DispatchQueue.main.async {
                    guard let self = self, self.attempt == current else {
                        UITrace.event("auth.stale_reply", ["attempt": current.uuidString])
                        return
                    }
                    self.state = success ? .success : .failure
                }
            }
        }
    }

    func cancel() {
        UITrace.event("auth.cancel", ["context": UITrace.id(context), "attempt": attempt.uuidString])
        attempt = UUID()
        pending = false
        context.invalidate()
        state = .cancelled
    }

    deinit {
        UITrace.event("auth.destroyed", ["context": UITrace.id(context)])
        context.invalidate()
    }
}

final class GalleryModel: NSObject, ObservableObject, NSWindowDelegate {
    static let scenarios = ["signing", "tag", "push", "pull", "fetch", "clone", "ls-remote", "secrets", "revoked", "long"]
    static let providers = ["github", "gitlab", "bitbucket", "generic"]
    private let defaults: UserDefaults
    private static let settingsKey = "seccy.gallery.settings.v1"
    @Published var state: AuthorizationState = .authenticating {
        didSet { UITrace.event("controls.state", ["value": state.rawValue]); saveSettings() }
    }
    @Published var scenario = "signing" {
        didSet { UITrace.event("controls.scenario", ["value": scenario]); saveSettings() }
    }
    @Published var hosting = "github" {
        didSet { UITrace.event("controls.hosting", ["value": hosting]); saveSettings() }
    }
    @Published var keyName = "work" { didSet { saveSettings() } }
    @Published var directory = "~/code/seccy" { didSet { saveSettings() } }
    var supportsHosting: Bool {
        ["push", "pull", "fetch", "clone", "ls-remote"].contains(scenario)
    }
    @Published var appearance = "system" { didSet { UITrace.event("controls.appearance", ["value": appearance]); applyAppearance(); saveSettings() } }
    @Published var live = true { didSet { UITrace.event("controls.live", ["value": String(live)]); authentication.cancel(); saveSettings() } }
    @Published var notificationStatus = ""
    @Published private(set) var capturedRequest: AuthorizationRequest?
    @Published private(set) var captureName = ""
    @Published var captureError = ""
    @Published private(set) var captureID = UUID()
    var usesLiveAuthentication: Bool { live && capturedRequest == nil }
    let authentication = GalleryAuthentication()
    private var previewWindow: NSWindow?

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        let settings = defaults.dictionary(forKey: Self.settingsKey) ?? [:]
        if let value = settings["scenario"] as? String, Self.scenarios.contains(value) { scenario = value }
        if let value = settings["hosting"] as? String, Self.providers.contains(value) { hosting = value }
        if let value = settings["appearance"] as? String, ["system", "light", "dark"].contains(value) { appearance = value }
        if let value = settings["state"] as? String, let state = AuthorizationState(rawValue: value) { self.state = state }
        if let value = settings["live"] as? Bool { live = value }
        if let value = settings["key"] as? String { keyName = value }
        if let value = settings["directory"] as? String { directory = value }
        super.init()
    }

    private func saveSettings() {
        defaults.set(["scenario": scenario, "hosting": hosting, "appearance": appearance,
                      "state": state.rawValue, "live": live, "key": keyName,
                      "directory": directory], forKey: Self.settingsKey)
    }

    var request: AuthorizationRequest {
        capturedRequest ?? fixture.preview(key: keyName, directory: directory)
    }

    func loadCapture(from url: URL) throws {
        let capture = try RequestCapture.read(from: url)
        authentication.cancel()
        capturedRequest = capture.replayRequest
        captureName = url.lastPathComponent
        captureError = ""
        captureID = UUID()
        state = .ready
    }

    func clearCapture() {
        capturedRequest = nil
        captureName = ""
        captureError = ""
        captureID = UUID()
    }

    func chooseCapture(from window: NSWindow?) {
        let panel = NSOpenPanel()
        panel.title = Copy.text("gallery-capture-open")
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        let level = previewWindow?.level
        previewWindow?.level = .normal
        let complete: (NSApplication.ModalResponse) -> Void = { [weak self] response in
            guard let self = self else { return }
            defer { if let level = level { self.previewWindow?.level = level } }
            guard response == .OK, let url = panel.url else { return }
            do {
                try self.loadCapture(from: url)
                self.show()
            } catch { self.captureError = error.localizedDescription }
        }
        if let window = window { panel.beginSheetModal(for: window, completionHandler: complete) }
        else { panel.begin(completionHandler: complete) }
    }

    private var fixture: AuthorizationRequest {
        if supportsHosting { return Copy.fixture("\(scenario)-\(hosting)") }
        switch scenario {
        case "secrets": return .secrets
        case "revoked": return .revoked
        case "long": return .long
        case "tag": return Copy.fixture("tag")
        default: return .signing
        }
    }

    func chooseDirectory(from window: NSWindow?) {
        let panel = NSOpenPanel()
        panel.title = Copy.text("gallery-directory-panel")
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.directoryURL = URL(fileURLWithPath: (directory as NSString).expandingTildeInPath)
        // Keep the preview from covering the folder picker while it is open.
        let level = previewWindow?.level
        previewWindow?.level = .normal
        let complete: (NSApplication.ModalResponse) -> Void = { [weak self] response in
            guard let self = self else { return }
            if response == .OK, let url = panel.url {
                self.directory = AuthorizationRequest.abbreviatedDirectory(url.path)
            }
            if let level = level { self.previewWindow?.level = level }
        }
        if let window = window {
            panel.beginSheetModal(for: window, completionHandler: complete)
        } else {
            panel.begin(completionHandler: complete)
        }
    }

    func show() {
        UITrace.event("window.show", ["existing": UITrace.id(previewWindow)])
        if previewWindow == nil {
            let window = makeAuthorizationWindow(GalleryPrompt(model: self, authentication: authentication))
            window.delegate = self
            previewWindow = window
            applyAppearance()
        }
        if let window = previewWindow { showAuthorizationWindow(window) }
    }

    func start() {
        show()
        guard capturedRequest == nil else { return }
        if live { authentication.start() } else { state = .authenticating }
    }

    func close() {
        UITrace.event("window.close_requested")
        previewWindow?.close()
    }

    func windowDidBecomeKey(_ notification: Notification) { UITrace.event("window.key") }
    func windowDidResignKey(_ notification: Notification) { UITrace.event("window.resigned_key") }
    func windowDidResize(_ notification: Notification) { UITrace.event("window.resize") }
    func windowDidMove(_ notification: Notification) { UITrace.event("window.move") }
    func windowDidExpose(_ notification: Notification) { UITrace.event("window.expose") }

    func windowWillClose(_ notification: Notification) {
        UITrace.event("window.closed")
        authentication.cancel()
        previewWindow?.contentViewController = nil
        previewWindow = nil
    }

    private func applyAppearance() {
        previewWindow?.appearance = appearance == "system" ? nil : NSAppearance(named: appearance == "dark" ? .darkAqua : .aqua)
    }

    func notify() {
        UITrace.event("notification.submit")
        guard let notification = request.notification else { return }
        notificationStatus = Copy.text("gallery-notification-submitting")
        let submission = NativeNotifications.shared.send(title: notification.title, body: notification.body) { [weak self] result in
            DispatchQueue.main.async {
                switch result {
                case .success:
                    self?.notificationStatus = Copy.text("gallery-notification-submitted")
                case .failure(let error): self?.notificationStatus = error.message
                }
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 120) { submission.cancel() }
    }
}

private struct GalleryPrompt: View {
    @ObservedObject var model: GalleryModel
    @ObservedObject var authentication: GalleryAuthentication
    var body: some View {
        let _ = UITrace.event("preview.body")
        AuthorizationView(request: model.request,
                           state: model.usesLiveAuthentication ? authentication.state : model.state,
                           context: model.usesLiveAuthentication ? authentication.context : nil,
                           fingerprintAppeared: { context in
                               if model.usesLiveAuthentication && context === authentication.context {
                                   authentication.appeared()
                               }
                           },
                           retry: { model.start() }, cancel: { model.close() })
            .id(model.captureID)
    }
}

struct GalleryView: View {
    @StateObject private var model = GalleryModel()
    var body: some View {
        let _ = UITrace.event("controls.body")
        VStack(alignment: .leading, spacing: 18) {
            Text(Copy.text("gallery-title")).font(.title2.bold())
            Text(Copy.text("gallery-description"))
                .font(.callout).foregroundStyle(UIPalette.secondary)
            HStack {
                Button(Copy.text("gallery-capture-open")) { model.chooseCapture(from: NSApp.keyWindow) }
                if model.capturedRequest != nil {
                    Button(Copy.text("gallery-capture-clear")) { model.clearCapture() }
                }
            }
            if model.capturedRequest != nil {
                Text(AuthorizationRequest.display(model.captureName)).font(.caption).textSelection(.enabled)
                Text(Copy.text("gallery-capture-replay")).font(.caption).foregroundStyle(UIPalette.secondary)
            }
            if !model.captureError.isEmpty {
                Text(model.captureError).font(.caption).foregroundStyle(UIPalette.error)
            }
            Picker(Copy.text("gallery-request"), selection: $model.scenario) {
                ForEach(GalleryModel.scenarios, id: \.self) { Text(Copy.text("gallery-scenario-" + $0)).tag($0) }
            }
            .disabled(model.capturedRequest != nil)
            Picker(Copy.text("gallery-hosting"), selection: $model.hosting) {
                ForEach(GalleryModel.providers, id: \.self) {
                    Text(Copy.text("gallery-hosting-" + $0)).tag($0)
                }
            }
            .disabled(!model.supportsHosting || model.capturedRequest != nil)
            TextField(Copy.text("gallery-key"), text: $model.keyName).textFieldStyle(.roundedBorder)
                .disabled(model.capturedRequest != nil)
            HStack {
                TextField(Copy.text("gallery-directory"), text: $model.directory).textFieldStyle(.roundedBorder)
                Button(Copy.text("gallery-directory-choose")) {
                    model.chooseDirectory(from: NSApp.keyWindow)
                }
            }
            .disabled(model.capturedRequest != nil)
            Toggle(Copy.text("gallery-live"), isOn: Binding(
                get: { model.usesLiveAuthentication }, set: { model.live = $0 }))
                .disabled(model.capturedRequest != nil)
            if !model.usesLiveAuthentication {
                Picker(Copy.text("gallery-state"), selection: $model.state) {
                    ForEach(AuthorizationState.allCases) { Text($0.label).tag($0) }
                }
            }
            Picker(Copy.text("gallery-appearance"), selection: $model.appearance) {
                ForEach(["system", "light", "dark"], id: \.self) { Text(Copy.text("gallery-appearance-" + $0)).tag($0) }
            }
            HStack {
                Button(Copy.text("gallery-show")) { model.show() }
                Button(Copy.text("gallery-start")) { model.start() }.disabled(!model.usesLiveAuthentication)
            }
            Divider()
            Text(Copy.text("gallery-notifications")).font(.headline)
            Text(Copy.text("gallery-notification-description"))
                .font(.caption).foregroundStyle(UIPalette.secondary)
            Button(Copy.text("gallery-notification-send")) { model.notify() }
                .disabled(model.capturedRequest != nil)
            Text(model.notificationStatus).font(.caption).foregroundStyle(UIPalette.secondary)
        }
        .padding(24).frame(width: 360)
        .onAppear { model.show() }
        .onDisappear { model.close() }
    }
}

struct AuthorizationView_Previews: PreviewProvider {
    static var previews: some View {
        AuthorizationView(request: .signing, state: .ready)
    }
}
