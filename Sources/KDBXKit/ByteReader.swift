import Foundation

/// Little-endian cursor over a byte buffer.
struct ByteReader {
    let bytes: [UInt8]
    private(set) var position = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    var remaining: Int { bytes.count - position }
    var isAtEnd: Bool { position >= bytes.count }

    mutating func read(_ count: Int) throws -> [UInt8] {
        guard count >= 0, count <= remaining else { throw KDBXError.corrupt("Unexpected end of data") }
        defer { position += count }
        return Array(bytes[position..<(position + count)])
    }

    mutating func readUInt8() throws -> UInt8 { try read(1)[0] }

    mutating func readUInt16() throws -> UInt16 {
        let b = try read(2)
        return UInt16(b[0]) | UInt16(b[1]) << 8
    }

    mutating func readUInt32() throws -> UInt32 {
        let b = try read(4)
        return b.enumerated().reduce(0) { $0 | UInt32($1.element) << (8 * UInt32($1.offset)) }
    }

    mutating func readUInt64() throws -> UInt64 {
        let b = try read(8)
        return b.enumerated().reduce(0) { $0 | UInt64($1.element) << (8 * UInt64($1.offset)) }
    }

    mutating func readInt32() throws -> Int32 { Int32(bitPattern: try readUInt32()) }
}

extension Array where Element == UInt8 {
    static func le32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) } }
    static func le64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) } }

    init?(hex: String) {
        let chars = [Character](hex.filter { !$0.isWhitespace })
        guard chars.count % 2 == 0 else { return nil }
        var out = [UInt8]()
        out.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let b = UInt8(String(chars[i..<i + 2]), radix: 16) else { return nil }
            out.append(b)
            i += 2
        }
        self = out
    }
}
