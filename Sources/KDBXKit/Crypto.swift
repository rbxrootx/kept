import CommonCrypto
import CryptoKit
import Foundation

public enum KDBXError: LocalizedError, Equatable {
    case notKeePassFile
    case unsupportedVersion(UInt32)
    case unsupportedCipher
    case unsupportedKDF
    case unsupportedInnerStream(UInt32)
    case invalidCredentials
    case corrupt(String)
    case keyFile(String)

    public var errorDescription: String? {
        switch self {
        case .notKeePassFile: "This file isn’t a KeePass database."
        case .unsupportedVersion(let v): "KDBX version \(v >> 16).\(v & 0xFFFF) isn’t supported."
        case .unsupportedCipher: "This database uses a cipher that isn’t supported (Twofish)."
        case .unsupportedKDF: "This database uses an unsupported key derivation function."
        case .unsupportedInnerStream(let id): "Unsupported protected-value stream (\(id))."
        case .invalidCredentials: "The password or key file is incorrect."
        case .corrupt(let reason): "The database appears to be damaged: \(reason)"
        case .keyFile(let reason): "Couldn’t read the key file: \(reason)"
        }
    }
}

enum Hash {
    static func sha256(_ data: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: data)) }
    static func sha512(_ data: [UInt8]) -> [UInt8] { Array(SHA512.hash(data: data)) }
    static func hmacSHA256(key: [UInt8], data: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }
}

enum AES {
    /// KeePass AES-KDF: encrypt the 32-byte key `rounds` times with AES-256-ECB keyed by `seed`, then SHA-256.
    static func transformKey(_ key: [UInt8], seed: [UInt8], rounds: UInt64) throws -> [UInt8] {
        guard seed.count == 32, key.count == 32 else { throw KDBXError.corrupt("Bad AES-KDF parameters") }
        var cryptor: CCCryptorRef?
        let status = seed.withUnsafeBytes {
            CCCryptorCreate(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                            $0.baseAddress, 32, nil, &cryptor)
        }
        guard status == kCCSuccess, let cryptor else { throw KDBXError.corrupt("AES init failed") }
        defer { CCCryptorRelease(cryptor) }

        var block = key
        var moved = 0
        try block.withUnsafeMutableBytes { buf in
            for _ in 0..<rounds {
                guard CCCryptorUpdate(cryptor, buf.baseAddress, 32, buf.baseAddress, 32, &moved) == kCCSuccess else {
                    throw KDBXError.corrupt("AES-KDF failed")
                }
            }
        }
        return Hash.sha256(block)
    }

    static func decryptCBC(_ data: [UInt8], key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        guard iv.count == 16, key.count == 32 else { throw KDBXError.corrupt("Bad AES parameters") }
        var out = [UInt8](repeating: 0, count: data.count + 16)
        var moved = 0
        let status = CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                             key, key.count, iv, data, data.count, &out, out.count, &moved)
        // A padding failure here almost always means the key is wrong.
        guard status == kCCSuccess else { throw KDBXError.invalidCredentials }
        out.removeSubrange(moved...)
        return out
    }
}

/// Keystream generator shared by Salsa20 and ChaCha20.
protocol StreamCipher {
    mutating func xor(_ data: inout [UInt8])
}

extension StreamCipher {
    mutating func process(_ data: [UInt8]) -> [UInt8] {
        var copy = data
        xor(&copy)
        return copy
    }
}

@inline(__always) private func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 { (x << n) | (x >> (32 - n)) }

private func loadLE32(_ b: [UInt8], _ i: Int) -> UInt32 {
    UInt32(b[i]) | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2]) << 16 | UInt32(b[i + 3]) << 24
}

struct Salsa20: StreamCipher {
    private var state = [UInt32](repeating: 0, count: 16)
    private var buffer = [UInt8](repeating: 0, count: 64)
    private var offset = 64

    init(key: [UInt8], nonce: [UInt8]) {
        precondition(key.count == 32 && nonce.count == 8)
        let sigma: [UInt32] = [0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574]
        state[0] = sigma[0]; state[5] = sigma[1]; state[10] = sigma[2]; state[15] = sigma[3]
        for i in 0..<4 { state[1 + i] = loadLE32(key, i * 4) }
        for i in 0..<4 { state[11 + i] = loadLE32(key, 16 + i * 4) }
        state[6] = loadLE32(nonce, 0)
        state[7] = loadLE32(nonce, 4)
    }

    private mutating func refill() {
        var x = state
        func qr(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            x[b] ^= rotl(x[a] &+ x[d], 7)
            x[c] ^= rotl(x[b] &+ x[a], 9)
            x[d] ^= rotl(x[c] &+ x[b], 13)
            x[a] ^= rotl(x[d] &+ x[c], 18)
        }
        for _ in 0..<10 {
            qr(0, 4, 8, 12); qr(5, 9, 13, 1); qr(10, 14, 2, 6); qr(15, 3, 7, 11)
            qr(0, 1, 2, 3); qr(5, 6, 7, 4); qr(10, 11, 8, 9); qr(15, 12, 13, 14)
        }
        for i in 0..<16 {
            let v = x[i] &+ state[i]
            for j in 0..<4 { buffer[i * 4 + j] = UInt8(truncatingIfNeeded: v >> (8 * UInt32(j))) }
        }
        state[8] &+= 1
        if state[8] == 0 { state[9] &+= 1 }
        offset = 0
    }

    mutating func xor(_ data: inout [UInt8]) {
        for i in data.indices {
            if offset == 64 { refill() }
            data[i] ^= buffer[offset]
            offset += 1
        }
    }
}

/// RFC 7539 ChaCha20 (96-bit nonce, 32-bit counter).
struct ChaCha20: StreamCipher {
    private var state = [UInt32](repeating: 0, count: 16)
    private var buffer = [UInt8](repeating: 0, count: 64)
    private var offset = 64

    init(key: [UInt8], nonce: [UInt8]) {
        precondition(key.count == 32 && nonce.count == 12)
        state[0] = 0x6170_7865; state[1] = 0x3320_646E; state[2] = 0x7962_2D32; state[3] = 0x6B20_6574
        for i in 0..<8 { state[4 + i] = loadLE32(key, i * 4) }
        state[12] = 0
        for i in 0..<3 { state[13 + i] = loadLE32(nonce, i * 4) }
    }

    private mutating func refill() {
        var x = state
        func qr(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            x[a] &+= x[b]; x[d] = rotl(x[d] ^ x[a], 16)
            x[c] &+= x[d]; x[b] = rotl(x[b] ^ x[c], 12)
            x[a] &+= x[b]; x[d] = rotl(x[d] ^ x[a], 8)
            x[c] &+= x[d]; x[b] = rotl(x[b] ^ x[c], 7)
        }
        for _ in 0..<10 {
            qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
            qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
        }
        for i in 0..<16 {
            let v = x[i] &+ state[i]
            for j in 0..<4 { buffer[i * 4 + j] = UInt8(truncatingIfNeeded: v >> (8 * UInt32(j))) }
        }
        state[12] &+= 1
        offset = 0
    }

    mutating func xor(_ data: inout [UInt8]) {
        for i in data.indices {
            if offset == 64 { refill() }
            data[i] ^= buffer[offset]
            offset += 1
        }
    }
}
