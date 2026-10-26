import KDBXKit
import SwiftUI

@main
struct KeptApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = AppModel.shared
    @AppStorage(Prefs.showMenuBarExtra) private var showMenuBarExtra = true

    var body: some Scene {
        Window("Kept", id: "main") {
            ContentView()
                .environment(model)
                .frame(minWidth: 760, minHeight: 460)
        }
        .defaultSize(width: 1100, height: 680)
        .commands { KeptCommands(model: model) }

        Settings {
            SettingsView()
                .environment(model)
        }

        MenuBarExtra("Kept", systemImage: "key.horizontal.fill", isInserted: $showMenuBarExtra) {
            MenuBarContent()
                .environment(model)
        }
    }
}

extension AppModel {
    static let shared = AppModel()
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        #if DEBUG
        // Used by Scripts/screenshots.sh; compiled out of release builds.
        if ProcessInfo.processInfo.environment["KEPT_DEBUG_APPEARANCE"] == "dark" {
            NSApp.appearance = NSAppearance(named: .darkAqua)
        }
        #endif
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func application(_ application: NSApplication, open urls: [URL]) {
        guard let url = urls.first(where: { $0.pathExtension.lowercased() == "kdbx" }) else { return }
        Task { @MainActor in AppModel.shared.select(url) }
    }
}

struct KeptCommands: Commands {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("Open Database…") {
                openWindow(id: "main")
                model.presentOpenPanel()
            }
            .keyboardShortcut("o")

            Menu("Open Recent") {
                ForEach(model.recentURLs, id: \.self) { url in
                    Button(url.lastPathComponent) {
                        openWindow(id: "main")
                        model.select(url)
                    }
                }
                Divider()
                Button("Clear Menu") { model.clearRecents() }
            }

            Divider()

            Button("Lock Database") { model.lock() }
                .keyboardShortcut("l")
                .disabled(model.phase != .unlocked)

            Button("Reload Database") { model.reload() }
                .keyboardShortcut("r")
                .disabled(model.phase != .unlocked)
        }

        CommandMenu("Entry") {
            let hasEntry = model.selectedEntry != nil
            Button("Copy Password") { model.copyPassword() }
                .keyboardShortcut("c", modifiers: [.command, .shift])
                .disabled(!hasEntry)
            Button("Copy User Name") { model.copyUsername() }
                .keyboardShortcut("b")
                .disabled(!hasEntry)
            Button("Copy Website") { model.copyURL() }
                .keyboardShortcut("u")
                .disabled(!hasEntry)
            Button("Copy Verification Code") { model.copyCode() }
                .keyboardShortcut("t", modifiers: [.command, .shift])
                .disabled(model.selectedEntry?.totp == nil)
            Divider()
            Button("Open Website") { model.openURL() }
                .keyboardShortcut("u", modifiers: [.command, .shift])
                .disabled(AppModel.webURL(model.selectedEntry?.url ?? "") == nil)
            Button(model.selectedEntry.map(model.isFavorite) == true ? "Remove from Favorites" : "Add to Favorites") {
                if let e = model.selectedEntry { model.toggleFavorite(e) }
            }
            .keyboardShortcut("d")
            .disabled(!hasEntry)
        }

        CommandGroup(after: .sidebar) {
            Button("Find") { model.focusSearch = true }
                .keyboardShortcut("f")
                .disabled(model.phase != .unlocked)
        }
    }
}
