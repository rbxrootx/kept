import CryptoKit
import Foundation

/// Time-based one-time passwords, read from the formats used by KeePassXC (`otp`) and KeePass 2.47+ (`TimeOtp-*`).
public struct TOTP: Hashable, Sendable {
    public enum Algorithm: String, Sendable { case sha1 = "SHA1", sha256 = "SHA256", sha512 = "SHA512" }

    public var secret: [UInt8]
    private var _digits = 6
    private var _period = 30
    public var algorithm = Algorithm.sha1

    static let storageKeys: Set<String> = [
        "otp", "TOTP Seed", "TOTP Settings",
        "TimeOtp-Secret", "TimeOtp-Secret-Hex", "TimeOtp-Secret-Base32", "TimeOtp-Secret-Base64",
        "TimeOtp-Length", "TimeOtp-Period", "TimeOtp-Algorithm",
    ]

    public var digits: Int { get { _digits } set { _digits = min(max(newValue, 4), 10) } }
    public var period: Int { get { _period } set { _period = min(max(newValue, 1), 86_400) } }

    public init(secret: [UInt8], digits: Int = 6, period: Int = 30, algorithm: Algorithm = .sha1) {
        self.secret = secret; self.algorithm = algorithm
        self.digits = digits; self.period = period
    }

    init?(entry: KDBXEntry) {
        func field(_ k: String) -> String? {
            let v = entry[field: k].trimmingCharacters(in: .whitespacesAndNewlines)
            return v.isEmpty ? nil : v
        }

        if let uri = field("otp") {
            if let parsed = TOTP(uri: uri) { self = parsed; return }
            if let key = Self.base32Decode(uri) { self.init(secret: key); return }
        }

        let secret = field("TimeOtp-Secret-Base32").flatMap(Self.base32Decode)
            ?? field("TimeOtp-Secret-Hex").flatMap { [UInt8](hex: $0) }
            ?? field("TimeOtp-Secret-Base64").flatMap { Data(base64Encoded: $0).map(Array.init) }
            ?? field("TimeOtp-Secret").map { Array($0.utf8) }
        if let secret {
            self.init(secret: secret)
            if let d = field("TimeOtp-Length").flatMap(Int.init) { digits = d }
            if let p = field("TimeOtp-Period").flatMap(Int.init) { period = p }
            switch field("TimeOtp-Algorithm") {
            case "HMAC-SHA-256": algorithm = .sha256
            case "HMAC-SHA-512": algorithm = .sha512
            default: break
            }
            return
        }

        if let seed = field("TOTP Seed").flatMap(Self.base32Decode) {
            self.init(secret: seed)
            if let settings = field("TOTP Settings")?.split(separator: ";"), settings.count >= 2 {
                period = Int(settings[0]) ?? 30
                digits = Int(settings[1]) ?? 6 // "S" (Steam) falls back to 6 digits
            }
            return
        }
        return nil
    }

    public init?(uri: String) {
        guard let components = URLComponents(string: uri), components.scheme == "otpauth" else { return nil }
        let items = Dictionary((components.queryItems ?? []).map { ($0.name.lowercased(), $0.value ?? "") },
                               uniquingKeysWith: { a, _ in a })
        guard let secret = items["secret"].flatMap(Self.base32Decode) else { return nil }
        self.init(secret: secret)
        if let d = items["digits"].flatMap(Int.init) { digits = d }
        if let p = items["period"].flatMap(Int.init), p > 0 { period = p }
        if let a = items["algorithm"].flatMap({ Algorithm(rawValue: $0.uppercased()) }) { algorithm = a }
    }

    public func code(at date: Date = Date()) -> String {
        let counter = UInt64(max(0, date.timeIntervalSince1970) / Double(period))
        let message = Data((0..<8).reversed().map { UInt8(truncatingIfNeeded: counter >> (8 * UInt64($0))) })
        let key = SymmetricKey(data: secret)
        let mac: [UInt8] = switch algorithm {
        case .sha1: Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256: Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512: Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }
        let offset = Int(mac[mac.count - 1] & 0x0F)
        let binary = (UInt32(mac[offset] & 0x7F) << 24) | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8) | UInt32(mac[offset + 3])
        var modulus: UInt32 = 1
        for _ in 0..<min(digits, 9) { modulus *= 10 }
        let code = String(binary % modulus)
        return String(repeating: "0", count: max(0, digits - code.count)) + code
    }

    public func secondsRemaining(at date: Date = Date()) -> Int {
        period - Int(date.timeIntervalSince1970) % period
    }

    static func base32Decode(_ string: String) -> [UInt8]? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits: UInt32 = 0, count = 0
        var out = [UInt8]()
        for ch in string.uppercased() where ch != "=" && ch != " " && ch != "-" {
            guard let idx = alphabet.firstIndex(of: ch) else { return nil }
            bits = (bits << 5) | UInt32(idx)
            count += 5
            if count >= 8 {
                out.append(UInt8(truncatingIfNeeded: bits >> UInt32(count - 8)))
                count -= 8
            }
        }
        return out.isEmpty ? nil : out
    }
}
