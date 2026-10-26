import Foundation

/// Streaming parser for the decrypted KeePass XML document.
///
/// Protected values are XOR-ed with the inner stream cipher in document order, so every protected
/// element (including those in entry history) must be visited even if its value is discarded.
final class XMLDatabaseParser: NSObject, XMLParserDelegate {
    private var stream: any StreamCipher
    private var binaries: [Data]

    private var path: [String] = []
    private var attributes: [[String: String]] = []
    private var text = ""

    private var databaseName = ""
    private var headerHash: [UInt8]?
    private var recycleBinID: UUID?
    private var customIcons: [UUID: Data] = [:]
    private var pendingIconID: UUID?
    private var pendingIconData: Data?

    private var groupStack: [KDBXGroup] = []
    private var root: KDBXGroup?
    private var entry: KDBXEntry?
    private var historyDepth = 0
    private var fieldKey = ""
    private var fieldValue = ""
    private var fieldProtected = false
    private var binaryKey = ""
    private var binaryRef: Int?
    private var failure: Error?

    private init(stream: any StreamCipher, binaries: [Data]) {
        self.stream = stream
        self.binaries = binaries
    }

    static func parse(_ xml: Data, stream: any StreamCipher, binaries: [Data], formatVersion: String) throws -> KDBXDatabase {
        let handler = XMLDatabaseParser(stream: stream, binaries: binaries)
        let parser = XMLParser(data: xml)
        parser.delegate = handler
        if !parser.parse() {
            throw handler.failure ?? KDBXError.corrupt(parser.parserError?.localizedDescription ?? "Invalid XML")
        }
        guard let root = handler.root else { throw KDBXError.corrupt("Database has no root group") }
        var db = KDBXDatabase(name: handler.databaseName.isEmpty ? root.name : handler.databaseName,
                              root: root, recycleBinID: handler.recycleBinID,
                              customIcons: handler.customIcons, formatVersion: formatVersion)
        db.headerHash = handler.headerHash
        return db
    }

    private var parent: String? { path.count >= 2 ? path[path.count - 2] : nil }
    private var inEntry: Bool { entry != nil && historyDepth == 0 }

    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?,
                qualifiedName: String?, attributes attrs: [String: String] = [:]) {
        path.append(name)
        attributes.append(attrs)
        text = ""

        switch name {
        case "Group" where entry == nil:
            groupStack.append(KDBXGroup(id: UUID()))
        case "Entry":
            if entry == nil {
                var e = KDBXEntry(id: UUID())
                e.groupPath = groupStack.map(\.name)
                e.groupID = groupStack.last?.id
                entry = e
            }
        case "History" where entry != nil:
            historyDepth += 1
        case "String" where inEntry:
            fieldKey = ""; fieldValue = ""; fieldProtected = false
        case "Binary" where inEntry && parent == "Entry":
            binaryKey = ""; binaryRef = nil
        default:
            break
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) { text += string }

    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
        defer {
            path.removeLast()
            attributes.removeLast()
            text = ""
        }
        let attrs = attributes.last ?? [:]
        var value = text

        if attrs["Protected"]?.caseInsensitiveCompare("True") == .orderedSame {
            let decoded = Array(Data(base64Encoded: value.trimmingCharacters(in: .whitespacesAndNewlines)) ?? Data())
            value = String(decoding: stream.process(decoded), as: UTF8.self)
        }

        let parent = self.parent
        let grandparent = path.count >= 3 ? path[path.count - 3] : nil

        switch (parent, name) {
        // Meta
        case ("Meta", "DatabaseName"): databaseName = value
        case ("Meta", "HeaderHash"):
            headerHash = Data(base64Encoded: value.trimmingCharacters(in: .whitespacesAndNewlines)).map(Array.init)
        case ("Meta", "RecycleBinUUID"): recycleBinID = Self.uuid(value)
        case ("Binaries", "Binary") where grandparent == "Meta":
            var data = Data(base64Encoded: value.trimmingCharacters(in: .whitespacesAndNewlines)) ?? Data()
            if attrs["Compressed"]?.caseInsensitiveCompare("True") == .orderedSame,
               let unzipped = try? Gzip.decompress(Array(data)) { data = Data(unzipped) }
            let id = Int(attrs["ID"] ?? "") ?? binaries.count
            guard (0...binaries.count + 1024).contains(id) else { break }
            if binaries.count <= id { binaries += Array(repeating: Data(), count: id - binaries.count + 1) }
            binaries[id] = data
        case ("Icon", "UUID"): pendingIconID = Self.uuid(value)
        case ("Icon", "Data"): pendingIconData = Data(base64Encoded: value.trimmingCharacters(in: .whitespacesAndNewlines))
        case ("CustomIcons", "Icon"):
            if let id = pendingIconID, let data = pendingIconData { customIcons[id] = data }
            pendingIconID = nil; pendingIconData = nil

        // Groups
        case ("Group", "UUID") where entry == nil: modifyGroup { $0.id = Self.uuid(value) ?? $0.id }
        case ("Group", "Name") where entry == nil: modifyGroup { $0.name = value }
        case ("Group", "Notes") where entry == nil: modifyGroup { $0.notes = value }
        case ("Group", "IconID") where entry == nil: modifyGroup { $0.iconID = Int(value) ?? $0.iconID }
        case ("Group", "CustomIconUUID") where entry == nil: modifyGroup { $0.customIconID = Self.uuid(value) }
        case (_, "Group") where entry == nil:
            guard let finished = groupStack.popLast() else { return }
            if groupStack.isEmpty {
                if root == nil { root = finished }
            } else {
                groupStack[groupStack.count - 1].groups.append(finished)
            }

        // Entries
        case ("Entry", "UUID") where inEntry: entry?.id = Self.uuid(value) ?? UUID()
        case ("Entry", "IconID") where inEntry: entry?.iconID = Int(value) ?? 0
        case ("Entry", "CustomIconUUID") where inEntry: entry?.customIconID = Self.uuid(value)
        case ("Entry", "Tags") where inEntry:
            entry?.tags = value.split(whereSeparator: { $0 == ";" || $0 == "," })
                .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        case ("Times", "CreationTime") where inEntry && grandparent == "Entry": entry?.created = Self.date(value)
        case ("Times", "LastModificationTime") where inEntry && grandparent == "Entry": entry?.modified = Self.date(value)
        case ("Times", "ExpiryTime") where inEntry && grandparent == "Entry": expiryTime = Self.date(value)
        case ("Times", "Expires") where inEntry && grandparent == "Entry": expiresFlag = value.lowercased() == "true"
        case ("String", "Key") where inEntry: fieldKey = value
        case ("String", "Value") where inEntry:
            fieldValue = value
            fieldProtected = attrs["Protected"]?.caseInsensitiveCompare("True") == .orderedSame
        case ("Entry", "String") where inEntry:
            entry?.fields.append(KDBXField(key: fieldKey, value: fieldValue, isProtected: fieldProtected))
        case ("Binary", "Key") where inEntry: binaryKey = value
        case ("Binary", "Value") where inEntry:
            if let refText = attrs["Ref"] {
                binaryRef = Int(refText).flatMap { $0 >= 0 ? $0 : nil }
            } else if !value.isEmpty, let inline = Data(base64Encoded: value) {
                entry?.attachments.append(KDBXAttachment(name: binaryKey, data: inline))
            }
        case ("Entry", "Binary") where inEntry:
            if let ref = binaryRef { pendingAttachments.append((binaryKey, ref)) }
        case ("History", "Entry") where historyDepth > 0:
            entry?.historyCount += 1
        case (_, "History") where entry != nil:
            historyDepth -= 1
        case (_, "Entry") where inEntry:
            if var finished = entry {
                finished.expires = expiresFlag ? expiryTime : nil
                // KDBX 3 binaries live in <Meta>, which always precedes <Root>, so refs resolve here.
                for (name, ref) in pendingAttachments where binaries.indices.contains(ref) {
                    finished.attachments.append(KDBXAttachment(name: name, data: binaries[ref]))
                }
                if !groupStack.isEmpty { groupStack[groupStack.count - 1].entries.append(finished) }
            }
            pendingAttachments.removeAll()
            expiresFlag = false
            expiryTime = nil
            entry = nil
        default:
            break
        }
    }

    private var pendingAttachments: [(String, Int)] = []
    private var expiresFlag = false
    private var expiryTime: Date?

    func parser(_ parser: XMLParser, parseErrorOccurred parseError: Error) {
        failure = failure ?? KDBXError.corrupt(parseError.localizedDescription)
    }

    private func modifyGroup(_ change: (inout KDBXGroup) -> Void) {
        guard !groupStack.isEmpty else { return }
        change(&groupStack[groupStack.count - 1])
    }

    static func uuid(_ base64: String) -> UUID? {
        guard let data = Data(base64Encoded: base64.trimmingCharacters(in: .whitespacesAndNewlines)) else { return nil }
        let id = KDBXReader.uuid(Array(data))
        return id == UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) ? nil : id
    }

    private static let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    static func date(_ value: String) -> Date? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.contains("-") { return isoFormatter.date(from: trimmed) }
        // KDBX 4: base64 of little-endian Int64 seconds since 0001-01-01.
        guard let data = Data(base64Encoded: trimmed), data.count == 8 else { return nil }
        let seconds = data.enumerated().reduce(Int64(0)) { $0 | Int64($1.element) << (8 * Int64($1.offset)) }
        return Date(timeIntervalSince1970: TimeInterval(seconds) - 62_135_596_800)
    }
}
