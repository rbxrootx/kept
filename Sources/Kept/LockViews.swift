import KDBXKit
import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            switch model.phase {
            case .welcome: WelcomeView()
            case .locked, .unlocking: UnlockView()
            case .unlocked: BrowserView()
            }
        }
        .overlay(alignment: .bottom) { ToastView() }
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first(where: { $0.pathExtension.lowercased() == "kdbx" }) else { return false }
            model.select(url)
            return true
        }
    }
}

struct ToastView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let message = model.toast {
            Label(message, systemImage: "checkmark.circle.fill")
                .font(.callout.weight(.medium))
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .background(.regularMaterial, in: Capsule())
                .overlay(Capsule().strokeBorder(.separator))
                .shadow(color: .black.opacity(0.12), radius: 8, y: 2)
                .padding(.bottom, 18)
                .transition(.move(edge: .bottom).combined(with: .opacity))
                .animation(.snappy, value: model.toast)
        }
    }
}

struct WelcomeView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 22) {
            AppGlyph(size: 84)
            VStack(spacing: 6) {
                Text("Kept").font(.largeTitle.weight(.semibold))
                Text("Open a KeePass database (.kdbx) to get started.")
                    .foregroundStyle(.secondary)
            }
            Button("Open Database…") { model.presentOpenPanel() }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .keyboardShortcut(.defaultAction)

            if !model.recentURLs.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Recent").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        .padding(.leading, 8)
                    ForEach(model.recentURLs, id: \.self) { url in
                        Button { model.select(url) } label: {
                            Label {
                                VStack(alignment: .leading) {
                                    Text(url.lastPathComponent)
                                    Text(url.deletingLastPathComponent().path(percentEncoded: false).abbreviatingWithTildeInPath)
                                        .font(.caption).foregroundStyle(.secondary)
                                        .lineLimit(1).truncationMode(.middle)
                                }
                            } icon: { Image(systemName: "lock.doc") }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 8).padding(.vertical, 4)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
                .frame(width: 340)
            }
            Text("You can also drop a .kdbx file onto this window.")
                .font(.caption).foregroundStyle(.tertiary)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct UnlockView: View {
    @Environment(AppModel.self) private var model
    @State private var password = ""
    @State private var keyFilePath: String?
    @State private var remember = true
    @State private var enterPassword = false
    @FocusState private var passwordFocused: Bool

    private var busy: Bool { model.phase == .unlocking }

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.fill")
                .font(.system(size: 40, weight: .medium))
                .foregroundStyle(.secondary)
                .frame(height: 50)

            VStack(spacing: 4) {
                Text(model.databaseURL?.deletingPathExtension().lastPathComponent ?? "Database")
                    .font(.title2.weight(.semibold))
                Text(model.databaseURL?.deletingLastPathComponent().path(percentEncoded: false).abbreviatingWithTildeInPath ?? "")
                    .font(.callout).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }

            if model.hasSavedCredentials && !enterPassword {
                savedCredentialsSection
            } else {
                passwordForm
            }

            if let error = model.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.callout)
                    .multilineTextAlignment(.center)
            }

            Button("Open a Different Database…") { model.presentOpenPanel() }
                .buttonStyle(.link)
                .font(.callout)
        }
        .frame(width: 340)
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .disabled(busy)
        .task(id: model.databaseURL) {
            password = ""
            keyFilePath = nil
            enterPassword = false
            await model.attemptAutoUnlock()
            passwordFocused = true
        }
    }

    private var savedCredentialsSection: some View {
        VStack(spacing: 12) {
            Button {
                Task { await model.unlockWithSavedCredentials() }
            } label: {
                Group {
                    if busy {
                        ProgressView().controlSize(.small)
                    } else if UserDefaults.standard.bool(forKey: Prefs.requireTouchID) {
                        Label("Unlock with \(Biometrics.label)", systemImage: "touchid")
                    } else {
                        Label("Unlock", systemImage: "lock.open.fill")
                    }
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)

            Button("Enter Password Instead") { enterPassword = true }
                .buttonStyle(.link)
                .font(.callout)
        }
    }

    private var passwordForm: some View {
        VStack(spacing: 12) {
            SecureField("Master Password", text: $password)
                .textFieldStyle(.roundedBorder)
                .controlSize(.large)
                .focused($passwordFocused)
                .onSubmit(submit)

            HStack {
                Image(systemName: "key").foregroundStyle(.secondary)
                if let keyFilePath {
                    Text(URL(fileURLWithPath: keyFilePath).lastPathComponent).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Button("Remove") { self.keyFilePath = nil }.buttonStyle(.link)
                } else {
                    Text("No key file").foregroundStyle(.secondary)
                    Spacer()
                    Button("Choose…", action: chooseKeyFile).buttonStyle(.link)
                }
            }
            .font(.callout)

            Toggle("Stay signed in (save to Keychain)", isOn: $remember)
                .toggleStyle(.checkbox)
                .frame(maxWidth: .infinity, alignment: .leading)

            Button(action: submit) {
                Group {
                    if busy { ProgressView().controlSize(.small) } else { Text("Unlock") }
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .disabled(password.isEmpty && keyFilePath == nil)
        }
    }

    private func submit() {
        guard !password.isEmpty || keyFilePath != nil else { return }
        Task {
            await model.unlock(password: password, keyFilePath: keyFilePath, remember: remember)
            if model.phase == .unlocked { password = "" }
        }
    }

    private func chooseKeyFile() {
        let panel = NSOpenPanel()
        panel.message = "Choose the key file for this database"
        panel.allowedContentTypes = [.data]
        if panel.runModal() == .OK { keyFilePath = panel.url?.path }
    }
}

/// The app's mark, drawn natively so it matches light and dark appearances.
struct AppGlyph: View {
    var size: CGFloat

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.225, style: .continuous)
            .fill(LinearGradient(colors: [Color(red: 0.25, green: 0.52, blue: 0.98), Color(red: 0.18, green: 0.33, blue: 0.86)],
                                 startPoint: .top, endPoint: .bottom))
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: "key.horizontal.fill")
                    .font(.system(size: size * 0.42, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .shadow(color: .black.opacity(0.15), radius: size * 0.06, y: size * 0.03)
    }
}

extension String {
    var abbreviatingWithTildeInPath: String { (self as NSString).abbreviatingWithTildeInPath }
}
