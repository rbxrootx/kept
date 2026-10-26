import KDBXKit
import SwiftUI

struct EntryDetailView: View {
    @Environment(AppModel.self) private var model
    let entry: KDBXEntry

    var body: some View {
        Form {
            Section {
                header
            }

            Section {
                if !entry.username.isEmpty {
                    FieldRow(label: "User Name", value: entry.username) { model.copyUsername(entry) }
                }
                if !entry.password.isEmpty {
                    FieldRow(label: "Password", value: entry.password, isSecret: true) { model.copyPassword(entry) }
                }
                if let totp = entry.totp {
                    CodeRow(totp: totp) { model.copyCode(entry) }
                }
                if !entry.url.isEmpty {
                    WebsiteRow(url: entry.url) { model.copyURL(entry) }
                }
            }

            if !entry.notes.isEmpty {
                Section("Notes") {
                    Text(entry.notes)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }

            if !entry.customFields.isEmpty {
                Section("Additional Fields") {
                    ForEach(entry.customFields) { field in
                        FieldRow(label: field.key, value: field.value, isSecret: field.isProtected) {
                            model.copy(field.value, label: field.key, sensitive: field.isProtected)
                        }
                    }
                }
            }

            if !entry.attachments.isEmpty {
                Section("Attachments") {
                    ForEach(entry.attachments) { AttachmentRow(attachment: $0) }
                }
            }

            Section {
                if !entry.tags.isEmpty {
                    LabeledContent("Tags") {
                        HStack(spacing: 4) {
                            ForEach(entry.tags, id: \.self) { tag in
                                Text(tag)
                                    .font(.caption)
                                    .padding(.horizontal, 7).padding(.vertical, 2)
                                    .background(.quaternary, in: Capsule())
                            }
                        }
                    }
                }
                if let expires = entry.expires {
                    LabeledContent("Expires") {
                        Text(expires, style: .date)
                            .foregroundStyle(entry.isExpired ? .red : .secondary)
                    }
                }
                if let modified = entry.modified {
                    LabeledContent("Modified") { Text(modified.formatted(date: .abbreviated, time: .shortened)) }
                }
                if let created = entry.created {
                    LabeledContent("Created") { Text(created.formatted(date: .abbreviated, time: .shortened)) }
                }
                if entry.historyCount > 0 {
                    LabeledContent("History", value: entry.historyCount == 1 ? "1 previous version" : "\(entry.historyCount) previous versions")
                }
            }
            .foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button { model.toggleFavorite(entry) } label: {
                    Label(model.isFavorite(entry) ? "Unfavorite" : "Favorite",
                          systemImage: model.isFavorite(entry) ? "star.fill" : "star")
                }
                .help(model.isFavorite(entry) ? "Remove from Favorites (⌘D)" : "Add to Favorites (⌘D)")

                Button { model.copyPassword(entry) } label: { Label("Copy Password", systemImage: "key") }
                    .help("Copy Password (⇧⌘C)")
                    .disabled(entry.password.isEmpty)
            }
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            EntryIcon(entry: entry, size: 52)
            VStack(alignment: .leading, spacing: 3) {
                Text(entry.title.isEmpty ? "Untitled" : entry.title)
                    .font(.title2.weight(.semibold))
                    .textSelection(.enabled)
                // The root group is implied, so only show the path below it.
                let path = entry.groupPath.count > 1 ? Array(entry.groupPath.dropFirst()) : entry.groupPath
                if !path.isEmpty {
                    Label(path.joined(separator: " › "), systemImage: "folder")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer()
            Button { model.toggleFavorite(entry) } label: {
                Image(systemName: model.isFavorite(entry) ? "star.fill" : "star")
                    .font(.title2)
                    .foregroundStyle(model.isFavorite(entry) ? .yellow : .secondary)
                    .contentTransition(.symbolEffect(.replace))
            }
            .buttonStyle(.plain)
            .help(model.isFavorite(entry) ? "Remove from Favorites" : "Add to Favorites")
        }
        .padding(.vertical, 4)
    }
}

/// A labelled value with a copy button; secrets are masked until revealed.
private struct FieldRow: View {
    let label: String
    let value: String
    var isSecret = false
    let copy: () -> Void

    @State private var revealed = false
    @State private var hovering = false

    var body: some View {
        LabeledContent {
            HStack(spacing: 8) {
                Group {
                    if isSecret && !revealed {
                        Text(String(repeating: "•", count: min(max(value.count, 8), 16)))
                            .foregroundStyle(.secondary)
                    } else if isSecret {
                        Text(Self.colorized(value))
                            .font(.body.monospaced())
                            .textSelection(.enabled)
                    } else {
                        Text(value).textSelection(.enabled)
                    }
                }
                .lineLimit(isSecret ? 1 : 3)
                .truncationMode(.middle)

                if isSecret {
                    Button { revealed.toggle() } label: {
                        Image(systemName: revealed ? "eye.slash" : "eye")
                    }
                    .buttonStyle(.borderless)
                    .help(revealed ? "Hide" : "Show")
                }
                CopyButton(action: copy).opacity(hovering ? 1 : 0.35)
            }
        } label: {
            Text(label)
        }
        .onHover { hovering = $0 }
    }

    /// Digits and symbols tinted like Passwords.app, to make similar characters easier to tell apart.
    static func colorized(_ password: String) -> AttributedString {
        var result = AttributedString()
        for ch in password {
            var piece = AttributedString(String(ch))
            if ch.isNumber {
                piece.foregroundColor = .blue
            } else if !ch.isLetter {
                piece.foregroundColor = .orange
            }
            result += piece
        }
        return result
    }
}

private struct CopyButton: View {
    let action: () -> Void

    var body: some View {
        Button(action: action) { Image(systemName: "doc.on.doc") }
            .buttonStyle(.borderless)
            .help("Copy")
    }
}

private struct WebsiteRow: View {
    let url: String
    let copy: () -> Void

    var body: some View {
        LabeledContent("Website") {
            HStack(spacing: 8) {
                if let link = AppModel.webURL(url) {
                    Link(destination: link) {
                        Text(url).lineLimit(1).truncationMode(.middle)
                    }
                    .help(link.absoluteString)
                } else {
                    Text(url).textSelection(.enabled)
                }
                CopyButton(action: copy)
            }
        }
    }
}

private struct CodeRow: View {
    let totp: TOTP
    let copy: () -> Void

    var body: some View {
        LabeledContent("Verification Code") {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                let remaining = totp.secondsRemaining(at: context.date)
                HStack(spacing: 10) {
                    Text(Self.grouped(totp.code(at: context.date)))
                        .font(.title3.monospacedDigit().weight(.medium))
                        .textSelection(.enabled)
                    ZStack {
                        Circle().stroke(.quaternary, lineWidth: 2.5)
                        Circle()
                            .trim(from: 0, to: CGFloat(remaining) / CGFloat(totp.period))
                            .stroke(remaining <= 5 ? Color.red : Color.accentColor,
                                    style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                            .animation(.linear(duration: 1), value: remaining)
                        Text("\(remaining)").font(.system(size: 8).monospacedDigit())
                    }
                    .frame(width: 20, height: 20)
                    CopyButton(action: copy)
                }
            }
        }
    }

    static func grouped(_ code: String) -> String {
        guard code.count == 6 || code.count == 8 else { return code }
        let mid = code.index(code.startIndex, offsetBy: code.count / 2)
        return "\(code[..<mid]) \(code[mid...])"
    }
}

private struct AttachmentRow: View {
    let attachment: KDBXAttachment

    var body: some View {
        LabeledContent {
            Button("Save…", action: save).buttonStyle(.borderless)
        } label: {
            Label {
                VStack(alignment: .leading) {
                    Text(attachment.name)
                    Text(ByteCountFormatter.string(fromByteCount: Int64(attachment.data.count), countStyle: .file))
                        .font(.caption).foregroundStyle(.secondary)
                }
            } icon: {
                Image(nsImage: NSWorkspace.shared.icon(for: .init(filenameExtension: (attachment.name as NSString).pathExtension) ?? .data))
                    .resizable().frame(width: 24, height: 24)
            }
        }
    }

    private func save() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = attachment.name
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? attachment.data.write(to: url, options: .atomic)
    }
}
