import AppKit
import LocalAuthentication
import Security

/// Stores database credentials in the login keychain so the app can stay signed in.
enum KeychainStore {
    struct Credentials: Codable {
        var password: String?
        var keyFilePath: String?
    }

    private static let service = "Kept Database Credentials"

    private static func baseQuery(_ url: URL) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: url.standardizedFileURL.path,
        ]
    }

    static func save(_ credentials: Credentials, for url: URL) throws {
        let data = try JSONEncoder().encode(credentials)
        SecItemDelete(baseQuery(url) as CFDictionary)
        var query = baseQuery(url)
        query[kSecValueData as String] = data
        query[kSecAttrLabel as String] = "Kept: \(url.lastPathComponent)"
        query[kSecAttrDescription as String] = "KeePass database password"
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error"])
        }
    }

    static func load(for url: URL) -> Credentials? {
        var query = baseQuery(url)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data else {
            return nil
        }
        return try? JSONDecoder().decode(Credentials.self, from: data)
    }

    /// Checks for a saved item without reading its secret (never prompts).
    static func hasCredentials(for url: URL) -> Bool {
        var query = baseQuery(url)
        query[kSecReturnAttributes as String] = true
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    static func delete(for url: URL) {
        SecItemDelete(baseQuery(url) as CFDictionary)
    }
}

enum Biometrics {
    static var isAvailable: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    static var label: String {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return context.biometryType == .touchID ? "Touch ID" : "your Mac password"
    }

    /// Touch ID with fallback to the user's login password.
    static func authenticate(reason: String) async -> Bool {
        let context = LAContext()
        context.localizedFallbackTitle = "Use Password…"
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }
}

@MainActor
enum Clipboard {
    private static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    private static let transientType = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
    private static var clearTask: Task<Void, Never>?

    /// Copies text. Sensitive values are marked concealed (so clipboard managers skip them)
    /// and cleared after the configured delay unless something else was copied since.
    static func copy(_ string: String, sensitive: Bool) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(string, forType: .string)
        if sensitive {
            pasteboard.setString(string, forType: concealedType)
            pasteboard.setString(string, forType: transientType)
        }

        clearTask?.cancel()
        let delay = UserDefaults.standard.object(forKey: Prefs.clipboardClearSeconds) as? Int ?? 30
        guard sensitive, delay > 0 else { return }
        let changeCount = pasteboard.changeCount
        clearTask = Task {
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled, pasteboard.changeCount == changeCount else { return }
            pasteboard.clearContents()
        }
    }
}

enum Prefs {
    static let clipboardClearSeconds = "clipboardClearSeconds"
    static let autoLockMinutes = "autoLockMinutes"
    static let lockOnScreenLock = "lockOnScreenLock"
    static let requireTouchID = "requireTouchID"
    static let showMenuBarExtra = "showMenuBarExtra"
    static let showRecycleBin = "showRecycleBin"
}

/// Watches a file for writes or replacement (e.g. when a sync service or KeePass saves it).
final class FileWatcher {
    private var source: DispatchSourceFileSystemObject?
    private let url: URL
    private let onChange: () -> Void

    init(url: URL, onChange: @escaping () -> Void) {
        self.url = url
        self.onChange = onChange
        start()
    }

    private func start() {
        let fd = open(url.path, O_EVTONLY)
        guard fd >= 0 else { return }
        let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: [.write, .rename, .delete],
                                                               queue: .main)
        source.setEventHandler { [weak self] in
            guard let self else { return }
            let replaced = !source.data.isDisjoint(with: [.rename, .delete])
            if replaced {
                // Atomic saves replace the file; re-attach to the new one.
                self.source?.cancel()
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.start(); self.onChange() }
            } else {
                self.onChange()
            }
        }
        source.setCancelHandler { close(fd) }
        source.resume()
        self.source = source
    }

    deinit { source?.cancel() }
}
