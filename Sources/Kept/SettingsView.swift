import KDBXKit
import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @AppStorage(Prefs.clipboardClearSeconds) private var clipboardClearSeconds = 30
    @AppStorage(Prefs.autoLockMinutes) private var autoLockMinutes = 0
    @AppStorage(Prefs.lockOnScreenLock) private var lockOnScreenLock = false
    @AppStorage(Prefs.requireTouchID) private var requireTouchID = false
    @AppStorage(Prefs.showMenuBarExtra) private var showMenuBarExtra = true
    @AppStorage(Prefs.showRecycleBin) private var showRecycleBin = false

    var body: some View {
        Form {
            Section("Clipboard") {
                Picker("Clear copied passwords", selection: $clipboardClearSeconds) {
                    Text("After 10 seconds").tag(10)
                    Text("After 30 seconds").tag(30)
                    Text("After 1 minute").tag(60)
                    Text("After 2 minutes").tag(120)
                    Text("Never").tag(0)
                }
            }

            Section {
                Picker("Lock automatically", selection: $autoLockMinutes) {
                    Text("Never").tag(0)
                    Text("After 5 minutes idle").tag(5)
                    Text("After 15 minutes idle").tag(15)
                    Text("After 1 hour idle").tag(60)
                    Text("After 4 hours idle").tag(240)
                }
                Toggle("Lock when the screen locks or Mac sleeps", isOn: $lockOnScreenLock)
                Toggle("Require \(Biometrics.label) to use saved password", isOn: $requireTouchID)
            } header: {
                Text("Security")
            } footer: {
                Text("Saved passwords are stored in your login keychain. Kept only reads your database; it never modifies it.")
                    .foregroundStyle(.secondary)
            }

            if let url = model.databaseURL, model.hasSavedCredentials {
                Section("Saved Password") {
                    LabeledContent(url.lastPathComponent) {
                        Button("Forget", role: .destructive) { model.forgetSavedPassword() }
                    }
                }
            }

            Section("Appearance") {
                Toggle("Show in menu bar", isOn: $showMenuBarExtra)
                Toggle("Show Recycle Bin group", isOn: $showRecycleBin)
            }
        }
        .formStyle(.grouped)
        .frame(width: 460)
        .fixedSize(horizontal: false, vertical: true)
    }
}

struct MenuBarContent: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if model.phase == .unlocked {
            let favorites = model.favoriteEntries
            if favorites.isEmpty {
                Text("No Favorites")
            } else {
                Section("Favorites") {
                    ForEach(favorites) { entry in
                        Menu(entry.title.isEmpty ? "Untitled" : entry.title) {
                            EntryActions(entry: entry)
                        }
                    }
                }
            }
            Divider()
            Button("Lock") { model.lock() }
        } else if model.databaseURL != nil {
            Button("Unlock…", action: showWindow)
        }
        Divider()
        Button("Open Kept", action: showWindow)
        SettingsLink { Text("Settings…") }
        Divider()
        Button("Quit Kept") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }

    private func showWindow() {
        openWindow(id: "main")
        NSApp.activate()
    }
}
