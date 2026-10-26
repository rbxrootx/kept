import Foundation

/// Builds the KeePass composite key from a password and/or key file.
public struct CompositeKey: Sendable {
    let raw: [UInt8]

    public init(password: String?, keyFileData: Data?) throws {
        var parts = [UInt8]()
        let hasKeyFile = keyFileData != nil
        if let password, !password.isEmpty || !hasKeyFile {
            parts += Hash.sha256(Array(password.utf8))
        } else if !hasKeyFile {
            parts += Hash.sha256([])
        }
        if let keyFileData { parts += try Self.keyFileKey(Array(keyFileData)) }
        raw = Hash.sha256(parts)
    }

    static func keyFileKey(_ data: [UInt8]) throws -> [UInt8] {
        if let xmlKey = try parseXMLKeyFile(data) { return xmlKey }
        if data.count == 32 { return data }
        if data.count == 64, let hex = [UInt8](hex: String(decoding: data, as: UTF8.self)), hex.count == 32 {
            return hex
        }
        return Hash.sha256(data)
    }

    private static func parseXMLKeyFile(_ data: [UInt8]) throws -> [UInt8]? {
        let text = String(decoding: data.prefix(4096), as: UTF8.self)
        guard text.contains("<KeyFile") else { return nil }
        let doc: XMLDocument
        do { doc = try XMLDocument(data: Data(data), options: [.nodeLoadExternalEntitiesNever]) } catch { return nil }

        let version = (try? doc.nodes(forXPath: "/KeyFile/Meta/Version").first?.stringValue) ?? "1.0"
        guard let dataNode = try doc.nodes(forXPath: "/KeyFile/Key/Data").first as? XMLElement,
              let content = dataNode.stringValue else {
            throw KDBXError.keyFile("Missing <Data> element")
        }
        if version.hasPrefix("2") {
            guard let key = [UInt8](hex: content), key.count == 32 else { throw KDBXError.keyFile("Invalid key data") }
            if let hashAttr = dataNode.attribute(forName: "Hash")?.stringValue,
               let expected = [UInt8](hex: hashAttr), Array(Hash.sha256(key).prefix(4)) != expected {
                throw KDBXError.keyFile("Checksum mismatch")
            }
            return key
        }
        guard let key = Data(base64Encoded: content.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw KDBXError.keyFile("Invalid key data")
        }
        return Array(key)
    }
}
