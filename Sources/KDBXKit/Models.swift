import Foundation

public struct KDBXField: Hashable, Sendable, Identifiable {
    public var key: String
    public var value: String
    public var isProtected: Bool
    public var id: String { key }
}

public struct KDBXAttachment: Hashable, Sendable, Identifiable {
    public var name: String
    public var data: Data
    public var id: String { name }
}

public struct KDBXEntry: Hashable, Sendable, Identifiable {
    public static let standardKeys: Set<String> = ["Title", "UserName", "Password", "URL", "Notes"]

    public var id: UUID
    public var fields: [KDBXField] = []
    public var attachments: [KDBXAttachment] = []
    public var tags: [String] = []
    public var iconID: Int = 0
    public var customIconID: UUID?
    public var created: Date?
    public var modified: Date?
    public var expires: Date?
    public var historyCount = 0
    /// Names of the groups from the root down to (and including) the containing group.
    public var groupPath: [String] = []
    public var groupID: UUID?

    public init(id: UUID) { self.id = id }

    public subscript(field key: String) -> String {
        fields.first { $0.key == key }?.value ?? ""
    }

    public var title: String { self[field: "Title"] }
    public var username: String { self[field: "UserName"] }
    public var password: String { self[field: "Password"] }
    public var url: String { self[field: "URL"] }
    public var notes: String { self[field: "Notes"] }

    public var customFields: [KDBXField] {
        fields.filter { !Self.standardKeys.contains($0.key) && !TOTP.storageKeys.contains($0.key) }
    }

    public var totp: TOTP? { TOTP(entry: self) }

    public var isExpired: Bool { expires.map { $0 < Date() } ?? false }
}

public struct KDBXGroup: Hashable, Sendable, Identifiable {
    public var id: UUID
    public var name: String = ""
    public var notes: String = ""
    public var iconID: Int = 48
    public var customIconID: UUID?
    public var groups: [KDBXGroup] = []
    public var entries: [KDBXEntry] = []

    public init(id: UUID) { self.id = id }

    /// Child groups, or nil for leaves (handy for `OutlineGroup`).
    public var children: [KDBXGroup]? { groups.isEmpty ? nil : groups }

    public var allEntries: [KDBXEntry] { entries + groups.flatMap(\.allEntries) }

    public func find(_ id: UUID) -> KDBXGroup? {
        if self.id == id { return self }
        for g in groups { if let found = g.find(id) { return found } }
        return nil
    }
}

public struct KDBXDatabase: Sendable {
    public var name: String
    public var root: KDBXGroup
    public var recycleBinID: UUID?
    public var customIcons: [UUID: Data]
    public var formatVersion: String
    /// KDBX 3.1 only: SHA-256 of the outer header as recorded in <Meta>.
    var headerHash: [UInt8]?

    /// All entries, excluding anything in the recycle bin.
    public var activeEntries: [KDBXEntry] {
        func collect(_ g: KDBXGroup) -> [KDBXEntry] {
            if g.id == recycleBinID { return [] }
            return g.entries + g.groups.flatMap(collect)
        }
        return collect(root)
    }

    public var allTags: [String] {
        Array(Set(activeEntries.flatMap(\.tags))).sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }
}
