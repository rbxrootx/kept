import Foundation

/// Reads and decrypts KDBX 3.1 and KDBX 4.x databases.
public enum KDBXReader {
    private static let signature1: UInt32 = 0x9AA2_D903
    private static let signature2: UInt32 = 0xB54B_FB67

    private enum CipherID {
        static let aes = UUID(uuidString: "31C1F2E6-BF71-4350-BE58-05216AFC5AFF")!
        static let chacha20 = UUID(uuidString: "D6038A2B-8B6F-4CB5-A524-339A31DBB59A")!
        static let twofish = UUID(uuidString: "AD68F29F-576F-4BB9-A36A-D47AF965346C")!
    }

    private enum KDFID {
        static let aes = UUID(uuidString: "C9D9F39A-628A-4460-BF74-0D08C18A4FEA")!
        static let aesKDBX4 = UUID(uuidString: "7C02BB82-79A7-4AC0-927D-114A00648238")!
        static let argon2d = UUID(uuidString: "EF636DDF-8C29-444B-91F7-A9A403E30A0C")!
        static let argon2id = UUID(uuidString: "9E298B19-56DB-4773-B23D-FC3EC6F0A1E6")!
    }

    private struct Header {
        var major: UInt16 = 0
        var minor: UInt16 = 0
        var cipher: UUID?
        var compressed = false
        var masterSeed: [UInt8] = []
        var transformSeed: [UInt8] = []
        var transformRounds: UInt64 = 0
        var iv: [UInt8] = []
        var protectedStreamKey: [UInt8] = []
        var streamStartBytes: [UInt8] = []
        var innerStreamID: UInt32 = 0
        var kdfParameters: [String: VariantValue] = [:]
        var rawBytes: [UInt8] = []
    }

    /// Convenience overload taking a password and optional key file.
    public static func open(data: Data, password: String?, keyFileData: Data? = nil) throws -> KDBXDatabase {
        try open(data: data, key: CompositeKey(password: password, keyFileData: keyFileData))
    }

    public static func open(data: Data, key: CompositeKey) throws -> KDBXDatabase {
        var reader = ByteReader(Array(data))
        guard reader.remaining >= 12,
              try reader.readUInt32() == signature1,
              try reader.readUInt32() == signature2 else { throw KDBXError.notKeePassFile }

        var header = Header()
        header.minor = try reader.readUInt16()
        header.major = try reader.readUInt16()
        guard header.major == 3 || header.major == 4 else {
            throw KDBXError.unsupportedVersion(UInt32(header.major) << 16 | UInt32(header.minor))
        }
        try readHeaderFields(&reader, into: &header)
        header.rawBytes = Array(reader.bytes[0..<reader.position])

        let transformed = try transformKey(key.raw, header: header)
        let version = "KDBX \(header.major).\(header.minor)"

        if header.major == 3 {
            return try openV3(&reader, header: header, transformedKey: transformed, version: version)
        }
        return try openV4(&reader, header: header, transformedKey: transformed, version: version)
    }

    // MARK: - Header

    private static func readHeaderFields(_ reader: inout ByteReader, into header: inout Header) throws {
        while true {
            let fieldID = try reader.readUInt8()
            let size = header.major >= 4 ? Int(try reader.readUInt32()) : Int(try reader.readUInt16())
            let value = try reader.read(size)
            switch fieldID {
            case 0: return
            case 2: header.cipher = uuid(value)
            case 3:
                var r = ByteReader(value)
                header.compressed = try r.readUInt32() == 1
            case 4: header.masterSeed = value
            case 5: header.transformSeed = value
            case 6:
                var r = ByteReader(value)
                header.transformRounds = try r.readUInt64()
            case 7: header.iv = value
            case 8: header.protectedStreamKey = value
            case 9: header.streamStartBytes = value
            case 10:
                var r = ByteReader(value)
                header.innerStreamID = try r.readUInt32()
            case 11: header.kdfParameters = try VariantDictionary.parse(value)
            default: break // comment, public custom data, etc.
            }
        }
    }

    private static func transformKey(_ composite: [UInt8], header: Header) throws -> [UInt8] {
        if header.major == 3 {
            return try AES.transformKey(composite, seed: header.transformSeed, rounds: header.transformRounds)
        }
        let p = header.kdfParameters
        guard case .bytes(let uuidBytes)? = p["$UUID"], let kdf = uuid(uuidBytes) else { throw KDBXError.unsupportedKDF }

        switch kdf {
        case KDFID.aes, KDFID.aesKDBX4:
            guard case .bytes(let seed)? = p["S"], let rounds = p["R"]?.integer else { throw KDBXError.unsupportedKDF }
            return try AES.transformKey(composite, seed: seed, rounds: rounds)
        case KDFID.argon2d, KDFID.argon2id:
            guard case .bytes(let salt)? = p["S"],
                  let iterations = p["I"]?.integer, let memory = p["M"]?.integer,
                  let parallelism = p["P"]?.integer, let version = p["V"]?.integer else {
                throw KDBXError.unsupportedKDF
            }
            // Parameters come from the (unauthenticated) header, so bound them before use.
            guard (1...Argon2.maxIterations).contains(iterations),
                  (8 * 1024...Argon2.maxMemoryBytes).contains(memory),
                  (1...Argon2.maxParallelism).contains(parallelism),
                  version == 0x10 || version == 0x13 else {
                throw KDBXError.corrupt("Unreasonable Argon2 parameters")
            }
            return try Argon2.hash(password: composite, salt: salt, iterations: UInt32(iterations),
                                   memoryKiB: UInt32(memory / 1024), parallelism: UInt32(parallelism),
                                   version: UInt32(version), variant: kdf == KDFID.argon2d ? .d : .id)
        default:
            throw KDBXError.unsupportedKDF
        }
    }

    private static func decrypt(_ payload: [UInt8], header: Header, key: [UInt8]) throws -> [UInt8] {
        switch header.cipher {
        case CipherID.aes?:
            return try AES.decryptCBC(payload, key: key, iv: header.iv)
        case CipherID.chacha20?:
            guard header.iv.count == 12 else { throw KDBXError.corrupt("Bad ChaCha20 nonce") }
            var cipher = ChaCha20(key: key, nonce: header.iv)
            return cipher.process(payload)
        default:
            throw KDBXError.unsupportedCipher
        }
    }

    // MARK: - KDBX 3.1

    private static func openV3(_ reader: inout ByteReader, header: Header, transformedKey: [UInt8],
                               version: String) throws -> KDBXDatabase {
        let masterKey = Hash.sha256(header.masterSeed + transformedKey)
        let plain = try decrypt(try reader.read(reader.remaining), header: header, key: masterKey)

        guard plain.count >= 32, Array(plain.prefix(32)) == header.streamStartBytes else {
            throw KDBXError.invalidCredentials
        }

        // Hashed block stream
        var blocks = ByteReader(Array(plain.dropFirst(32)))
        var content = [UInt8]()
        while true {
            _ = try blocks.readUInt32()
            let hash = try blocks.read(32)
            let size = Int(try blocks.readUInt32())
            if size == 0 { break }
            let data = try blocks.read(size)
            guard Hash.sha256(data) == hash else { throw KDBXError.corrupt("Block hash mismatch") }
            content += data
        }
        if header.compressed { content = try Gzip.decompress(content) }

        guard header.innerStreamID == 2 else { throw KDBXError.unsupportedInnerStream(header.innerStreamID) }
        let stream = Salsa20(key: Hash.sha256(header.protectedStreamKey),
                             nonce: [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A])
        let db = try XMLDatabaseParser.parse(Data(content), stream: stream, binaries: [], formatVersion: version)
        if let expected = db.headerHash, expected != Hash.sha256(header.rawBytes) {
            throw KDBXError.corrupt("Header checksum mismatch")
        }
        return db
    }

    // MARK: - KDBX 4.x

    private static func openV4(_ reader: inout ByteReader, header: Header, transformedKey: [UInt8],
                               version: String) throws -> KDBXDatabase {
        let headerHash = try reader.read(32)
        guard Hash.sha256(header.rawBytes) == headerHash else { throw KDBXError.corrupt("Header checksum mismatch") }

        let masterKey = Hash.sha256(header.masterSeed + transformedKey)
        let hmacBase = Hash.sha512(header.masterSeed + transformedKey + [1])
        func blockKey(_ index: UInt64) -> [UInt8] { Hash.sha512(.le64(index) + hmacBase) }

        let headerHMAC = try reader.read(32)
        guard Hash.hmacSHA256(key: blockKey(.max), data: header.rawBytes) == headerHMAC else {
            throw KDBXError.invalidCredentials
        }

        var payload = [UInt8]()
        var index: UInt64 = 0
        while true {
            let hmac = try reader.read(32)
            let sizeBytes = try reader.read(4)
            var sr = ByteReader(sizeBytes)
            let size = Int(try sr.readInt32())
            guard size >= 0 else { throw KDBXError.corrupt("Negative block size") }
            let data = try reader.read(size)
            guard Hash.hmacSHA256(key: blockKey(index), data: .le64(index) + sizeBytes + data) == hmac else {
                throw KDBXError.corrupt("Block authentication failed")
            }
            if size == 0 { break }
            payload += data
            index += 1
        }

        var plain = try decrypt(payload, header: header, key: masterKey)
        if header.compressed { plain = try Gzip.decompress(plain) }

        // Inner header
        var inner = ByteReader(plain)
        var streamID: UInt32 = 0
        var streamKey = [UInt8]()
        var binaries = [Data]()
        while true {
            let type = try inner.readUInt8()
            let size = Int(try inner.readUInt32())
            let value = try inner.read(size)
            if type == 0 { break }
            switch type {
            case 1:
                var r = ByteReader(value)
                streamID = try r.readUInt32()
            case 2: streamKey = value
            case 3: binaries.append(Data(value.dropFirst())) // first byte = flags
            default: break
            }
        }

        let stream: StreamCipher
        switch streamID {
        case 3:
            let h = Hash.sha512(streamKey)
            stream = ChaCha20(key: Array(h[0..<32]), nonce: Array(h[32..<44]))
        case 2:
            stream = Salsa20(key: Hash.sha256(streamKey), nonce: [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A])
        default:
            throw KDBXError.unsupportedInnerStream(streamID)
        }

        let xml = Data(plain[inner.position...])
        return try XMLDatabaseParser.parse(xml, stream: stream, binaries: binaries, formatVersion: version)
    }

    static func uuid(_ bytes: [UInt8]) -> UUID? {
        guard bytes.count == 16 else { return nil }
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}

// MARK: - Variant dictionary (KDBX 4 KDF parameters)

enum VariantValue {
    case uint32(UInt32), uint64(UInt64), bool(Bool), int32(Int32), int64(Int64), string(String), bytes([UInt8])

    var integer: UInt64? {
        switch self {
        case .uint32(let v): UInt64(v)
        case .uint64(let v): v
        case .int32(let v): UInt64(clamping: v)
        case .int64(let v): UInt64(clamping: v)
        default: nil
        }
    }
}

enum VariantDictionary {
    static func parse(_ bytes: [UInt8]) throws -> [String: VariantValue] {
        var r = ByteReader(bytes)
        let version = try r.readUInt16()
        guard version >> 8 == 1 else { throw KDBXError.corrupt("Unsupported KDF parameter format") }
        var result = [String: VariantValue]()
        while true {
            let type = try r.readUInt8()
            if type == 0 { break }
            let name = String(decoding: try r.read(Int(try r.readInt32())), as: UTF8.self)
            let raw = try r.read(Int(try r.readInt32()))
            var v = ByteReader(raw)
            switch type {
            case 0x04: result[name] = .uint32(try v.readUInt32())
            case 0x05: result[name] = .uint64(try v.readUInt64())
            case 0x08: result[name] = .bool(raw.first == 1)
            case 0x0C: result[name] = .int32(try v.readInt32())
            case 0x0D: result[name] = .int64(Int64(bitPattern: try v.readUInt64()))
            case 0x18: result[name] = .string(String(decoding: raw, as: UTF8.self))
            case 0x42: result[name] = .bytes(raw)
            default: break
            }
        }
        return result
    }
}

// MARK: - Gzip

enum Gzip {
    static func decompress(_ data: [UInt8]) throws -> [UInt8] {
        guard data.count >= 18, data[0] == 0x1F, data[1] == 0x8B, data[2] == 8 else {
            throw KDBXError.corrupt("Invalid gzip stream")
        }
        let flags = data[3]
        var offset = 10
        if flags & 0x04 != 0 { offset += 2 + Int(data[offset]) | Int(data[offset + 1]) << 8 }
        if flags & 0x08 != 0 { while offset < data.count && data[offset] != 0 { offset += 1 }; offset += 1 }
        if flags & 0x10 != 0 { while offset < data.count && data[offset] != 0 { offset += 1 }; offset += 1 }
        if flags & 0x02 != 0 { offset += 2 }
        guard offset < data.count - 8 else { throw KDBXError.corrupt("Invalid gzip stream") }

        let deflate = Data(data[offset..<(data.count - 8)])
        do {
            return Array(try (deflate as NSData).decompressed(using: .zlib) as Data)
        } catch {
            throw KDBXError.corrupt("Decompression failed")
        }
    }
}
