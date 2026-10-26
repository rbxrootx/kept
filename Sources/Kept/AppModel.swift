import AppKit
import KDBXKit
import Observation

enum SidebarItem: Hashable {
    case all, favorites, codes
    case tag(String)
    case group(UUID)
}

@MainActor
@Observable
final class AppModel {
    enum Phase: Equatable { case welcome, locked, unlocking, unlocked }

    private(set) var phase: Phase = .welcome
    private(set) var databaseURL: URL?
    private(set) var database: KDBXDatabase?
    private(set) var hasSavedCredentials = false
    private(set) var recentURLs: [URL] = []
    private(set) var favorites: Set<UUID> = []
    var errorMessage: String?
    var toast: String?

    var sidebarSelection: SidebarItem? = .all { didSet { saveSelection() } }
    var selectedEntryID: UUID? { didSet { saveSelection() } }
    var searchText = ""
    var focusSearch = false

    @ObservationIgnored private var session: (password: String?, keyFile: Data?, keyFilePath: String?)?
    @ObservationIgnored private var watcher: FileWatcher?
    @ObservationIgnored private var reloadTask: Task<Void, Never>?
    @ObservationIgnored private var toastTask: Task<Void, Never>?
    @ObservationIgnored private var idleTimer: Timer?
    @ObservationIgnored private var autoUnlockAttempted = false

    private let defaults = UserDefaults.standard

    init() {
        defaults.register(defaults: [
            Prefs.clipboardClearSeconds: 30,
            Prefs.autoLockMinutes: 0,
            Prefs.lockOnScreenLock: false,
            Prefs.requireTouchID: false,
            Prefs.showMenuBarExtra: true,
            Prefs.showRecycleBin: false,
        ])
        recentURLs = (defaults.stringArray(forKey: "recentDatabases") ?? [])
            .map { URL(fileURLWithPath: $0) }
            .filter { FileManager.default.fileExists(atPath: $0.path) }
        if let last = recentURLs.first { select(last) }
        observeSystemEvents()
    }

    // MARK: - Opening & unlocking

    func presentOpenPanel() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.init(filenameExtension: "kdbx")].compactMap { $0 }
        panel.allowsMultipleSelection = false
        panel.message = "Choose a KeePass database"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        select(url)
    }

    func select(_ url: URL) {
        if databaseURL != url { lock() }
        databaseURL = url
        hasSavedCredentials = KeychainStore.hasCredentials(for: url)
        autoUnlockAttempted = false
        errorMessage = nil
        if phase != .unlocked { phase = .locked }
        addRecent(url)
    }

    /// Called when the unlock screen appears: signs straight back in with saved credentials.
    func attemptAutoUnlock() async {
        #if DEBUG
        // Used by Scripts/screenshots.sh to open the demo database; compiled out of release builds.
        if phase == .locked, !autoUnlockAttempted, let password = ProcessInfo.processInfo.environment["KEPT_DEBUG_PASSWORD"] {
            autoUnlockAttempted = true
            await unlock(password: password, keyFilePath: nil, remember: false)
            return
        }
        #endif
        guard phase == .locked, hasSavedCredentials, !autoUnlockAttempted else { return }
        autoUnlockAttempted = true
        await unlockWithSavedCredentials()
    }

    func unlockWithSavedCredentials() async {
        guard let url = databaseURL else { return }
        if defaults.bool(forKey: Prefs.requireTouchID) {
            guard await Biometrics.authenticate(reason: "unlock “\(url.deletingPathExtension().lastPathComponent)”") else {
                return
            }
        }
        guard let saved = KeychainStore.load(for: url) else {
            hasSavedCredentials = KeychainStore.hasCredentials(for: url)
            if !hasSavedCredentials { errorMessage = "No saved password was found in the keychain." }
            return
        }
        await unlock(password: saved.password, keyFilePath: saved.keyFilePath, remember: false)
    }

    func unlock(password: String?, keyFilePath: String?, remember: Bool) async {
        guard let url = databaseURL else { return }
        phase = .unlocking
        errorMessage = nil
        do {
            let keyFile = try keyFilePath.map { try Data(contentsOf: URL(fileURLWithPath: $0)) }
            let db = try await Self.load(url: url, password: password, keyFile: keyFile)
            session = (password, keyFile, keyFilePath)
            if remember {
                try? KeychainStore.save(.init(password: password, keyFilePath: keyFilePath), for: url)
                hasSavedCredentials = true
            }
            apply(db)
            phase = .unlocked
            watcher = FileWatcher(url: url) { [weak self] in self?.scheduleReload() }
            restartIdleTimer()
        } catch {
            phase = .locked
            errorMessage = error.localizedDescription
            if (error as? KDBXError) == .invalidCredentials, !remember, hasSavedCredentials {
                errorMessage = "The saved password no longer works. Enter the current password."
            }
        }
    }

    private nonisolated static func load(url: URL, password: String?, keyFile: Data?) async throws -> KDBXDatabase {
        try await Task.detached(priority: .userInitiated) {
            let data = try Data(contentsOf: url)
            return try KDBXReader.open(data: data, password: password, keyFileData: keyFile)
        }.value
    }

    private func apply(_ db: KDBXDatabase) {
        database = db
        favorites = Set((defaults.dictionary(forKey: "favorites")?[favoritesKey(db)] as? [String] ?? [])
            .compactMap(UUID.init(uuidString:)))
        if phase != .unlocked { restoreSelection(db) }
        if let id = selectedEntryID, !db.activeEntries.contains(where: { $0.id == id }) { selectedEntryID = nil }
    }

    func lock() {
        guard phase == .unlocked || phase == .unlocking else { return }
        phase = .locked
        database = nil
        session = nil
        watcher = nil
        selectedEntryID = nil
        searchText = ""
        favorites = []
        autoUnlockAttempted = true // don't immediately sign back in after an explicit lock
    }

    func forgetSavedPassword() {
        guard let url = databaseURL else { return }
        KeychainStore.delete(for: url)
        hasSavedCredentials = false
    }

    func closeDatabase() {
        lock()
        databaseURL = nil
        phase = .welcome
    }

    func reload() {
        guard let url = databaseURL, let session, phase == .unlocked else { return }
        Task {
            do {
                apply(try await Self.load(url: url, password: session.password, keyFile: session.keyFile))
                showToast("Database reloaded")
            } catch {
                showToast("Couldn’t reload: \(error.localizedDescription)")
            }
        }
    }

    private func scheduleReload() {
        reloadTask?.cancel()
        reloadTask = Task {
            try? await Task.sleep(for: .milliseconds(600))
            guard !Task.isCancelled else { return }
            reload()
        }
    }

    // MARK: - Selection persistence

    /// Remembers the sidebar item and entry per database so the window reopens where it was left.
    private func saveSelection() {
        guard phase == .unlocked, let database else { return }
        let sidebar: String = switch sidebarSelection ?? .all {
        case .all: "all"
        case .favorites: "favorites"
        case .codes: "codes"
        case .tag(let tag): "tag:\(tag)"
        case .group(let id): "group:\(id.uuidString)"
        }
        var all = defaults.dictionary(forKey: "lastSelection") ?? [:]
        all[database.root.id.uuidString] = ["sidebar": sidebar, "entry": selectedEntryID?.uuidString ?? ""]
        defaults.set(all, forKey: "lastSelection")
    }

    private func restoreSelection(_ db: KDBXDatabase) {
        guard let saved = defaults.dictionary(forKey: "lastSelection")?[db.root.id.uuidString] as? [String: String] else {
            return
        }
        let sidebar = saved["sidebar"] ?? "all"
        sidebarSelection = switch sidebar {
        case "favorites": .favorites
        case "codes": .codes
        case _ where sidebar.hasPrefix("tag:"): .tag(String(sidebar.dropFirst(4)))
        case _ where sidebar.hasPrefix("group:"): UUID(uuidString: String(sidebar.dropFirst(6))).map { .group($0) } ?? .all
        default: .all
        }
        selectedEntryID = saved["entry"].flatMap(UUID.init(uuidString:))
    }

    // MARK: - Recents

    private func addRecent(_ url: URL) {
        recentURLs.removeAll { $0.standardizedFileURL == url.standardizedFileURL }
        recentURLs.insert(url, at: 0)
        recentURLs = Array(recentURLs.prefix(8))
        defaults.set(recentURLs.map(\.path), forKey: "recentDatabases")
        NSDocumentController.shared.noteNewRecentDocumentURL(url)
    }

    func clearRecents() {
        recentURLs = databaseURL.map { [$0] } ?? []
        defaults.set(recentURLs.map(\.path), forKey: "recentDatabases")
    }

    // MARK: - Favorites

    /// Favorites are keyed by the root group's UUID so they survive the file being moved or renamed.
    private func favoritesKey(_ db: KDBXDatabase) -> String { db.root.id.uuidString }

    func isFavorite(_ entry: KDBXEntry) -> Bool { favorites.contains(entry.id) }

    func toggleFavorite(_ entry: KDBXEntry) {
        guard let database else { return }
        if favorites.remove(entry.id) == nil { favorites.insert(entry.id) }
        var all = defaults.dictionary(forKey: "favorites") ?? [:]
        all[favoritesKey(database)] = favorites.map(\.uuidString)
        defaults.set(all, forKey: "favorites")
    }

    // MARK: - Browsing

    var selectedEntry: KDBXEntry? {
        guard let id = selectedEntryID else { return nil }
        return database?.activeEntries.first { $0.id == id }
            ?? database?.root.find(database?.recycleBinID ?? UUID())?.allEntries.first { $0.id == id }
    }

    var favoriteEntries: [KDBXEntry] { sorted((database?.activeEntries ?? []).filter { favorites.contains($0.id) }) }

    var visibleEntries: [KDBXEntry] {
        guard let database else { return [] }
        let query = searchText.trimmingCharacters(in: .whitespaces)
        if !query.isEmpty {
            return sorted(database.activeEntries.filter { entry in
                [entry.title, entry.username, entry.url, entry.notes, entry.tags.joined(separator: " ")]
                    .contains { $0.localizedCaseInsensitiveContains(query) }
            })
        }
        switch sidebarSelection ?? .all {
        case .all: return sorted(database.activeEntries)
        case .favorites: return favoriteEntries
        case .codes: return sorted(database.activeEntries.filter { $0.totp != nil })
        case .tag(let tag): return sorted(database.activeEntries.filter { $0.tags.contains(tag) })
        case .group(let id): return sorted(database.root.find(id)?.allEntries ?? [])
        }
    }

    var listTitle: String {
        if !searchText.isEmpty { return "Search Results" }
        switch sidebarSelection ?? .all {
        case .all: return "All Items"
        case .favorites: return "Favorites"
        case .codes: return "Verification Codes"
        case .tag(let tag): return tag
        case .group(let id): return database?.root.find(id)?.name ?? ""
        }
    }

    private func sorted(_ entries: [KDBXEntry]) -> [KDBXEntry] {
        entries.sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
    }

    // MARK: - Copying

    func copy(_ value: String, label: String, sensitive: Bool) {
        guard !value.isEmpty else { return }
        Clipboard.copy(value, sensitive: sensitive)
        let seconds = defaults.integer(forKey: Prefs.clipboardClearSeconds)
        showToast(sensitive && seconds > 0 ? "\(label) copied · clears in \(seconds)s" : "\(label) copied")
        restartIdleTimer()
    }

    func copyPassword(_ entry: KDBXEntry? = nil) {
        guard let e = entry ?? selectedEntry else { return }
        copy(e.password, label: "Password", sensitive: true)
    }

    func copyUsername(_ entry: KDBXEntry? = nil) {
        guard let e = entry ?? selectedEntry else { return }
        copy(e.username, label: "User name", sensitive: false)
    }

    func copyURL(_ entry: KDBXEntry? = nil) {
        guard let e = entry ?? selectedEntry else { return }
        copy(e.url, label: "Website", sensitive: false)
    }

    func copyCode(_ entry: KDBXEntry? = nil) {
        guard let e = entry ?? selectedEntry, let totp = e.totp else { return }
        copy(totp.code(), label: "Code", sensitive: true)
    }

    func openURL(_ entry: KDBXEntry? = nil) {
        guard let e = entry ?? selectedEntry, let url = Self.webURL(e.url) else { return }
        NSWorkspace.shared.open(url)
    }

    /// Only http(s) links are ever opened; other schemes (file://, cmd://, app URL schemes) are shown as text.
    nonisolated static func webURL(_ string: String) -> URL? {
        let trimmed = string.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.contains(" ") else { return nil }
        let candidate = trimmed.contains("://") ? URL(string: trimmed) : URL(string: "https://\(trimmed)")
        guard let url = candidate, ["http", "https"].contains(url.scheme?.lowercased()), url.host() != nil else {
            return nil
        }
        return url
    }

    func showToast(_ message: String) {
        toast = message
        toastTask?.cancel()
        toastTask = Task {
            try? await Task.sleep(for: .seconds(2))
            if !Task.isCancelled { toast = nil }
        }
    }

    // MARK: - Auto-lock

    private func observeSystemEvents() {
        let lockIfEnabled: @Sendable (Notification) -> Void = { [weak self] _ in
            Task { @MainActor in
                guard let self, self.defaults.bool(forKey: Prefs.lockOnScreenLock) else { return }
                self.lock()
            }
        }
        DistributedNotificationCenter.default().addObserver(forName: .init("com.apple.screenIsLocked"),
                                                            object: nil, queue: .main, using: lockIfEnabled)
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.willSleepNotification,
                                                          object: nil, queue: .main, using: lockIfEnabled)
    }

    /// Locks after the configured period of system-wide inactivity.
    func restartIdleTimer() {
        idleTimer?.invalidate()
        idleTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.phase == .unlocked else { return }
                let minutes = self.defaults.integer(forKey: Prefs.autoLockMinutes)
                guard minutes > 0 else { return }
                let idle = CGEventSource.secondsSinceLastEventType(.combinedSessionState,
                                                                   eventType: CGEventType(rawValue: ~0)!)
                if idle >= Double(minutes * 60) { self.lock() }
            }
        }
    }
}
