@testable import KDBXKit
import XCTest

final class KDBXKitTests: XCTestCase {
    private func fixture(_ name: String) throws -> Data {
        let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "kdbx", subdirectory: "Fixtures"))
        return try Data(contentsOf: url)
    }

    // Reference values from argon2-cffi.
    func testArgon2id() throws {
        let out = try Argon2.hash(password: Array("password".utf8), salt: Array("somesalt0000".utf8), iterations: 2,
                                  memoryKiB: 256, parallelism: 2, version: 0x13, variant: .id)
        XCTAssertEqual(hex(out), "a93e763bba95ddfbed94be82dfeed023e8fb2e124cc65aac28118e70a6a578fa")
    }

    func testArgon2d() throws {
        let out = try Argon2.hash(password: Array("password".utf8), salt: Array("somesalt0000".utf8), iterations: 3,
                                  memoryKiB: 64, parallelism: 1, version: 0x13, variant: .d)
        XCTAssertEqual(hex(out), "71d82f67aeda94dbb6ea80a8e659fd00e30ac8685796ba5a8f86e1e83c550c30")
    }

    func testKDBX4() throws {
        let db = try KDBXReader.open(data: fixture("v4"), password: "test-password")
        XCTAssertEqual(db.formatVersion, "KDBX 4.0")
        let entries = db.activeEntries
        let twitter = try XCTUnwrap(entries.first { $0.title == "Twitter" })
        XCTAssertEqual(twitter.username, "alex")
        XCTAssertEqual(twitter.password, "newer-pass")
        XCTAssertEqual(twitter.url, "https://x.com")
        XCTAssertEqual(twitter.notes, "line1\nline2")
        XCTAssertEqual(Set(twitter.tags), ["web", "social"])
        XCTAssertEqual(twitter.customFields.map(\.value), ["abcd-efgh"])
        XCTAssertEqual(twitter.historyCount, 1)
        XCTAssertEqual(twitter.groupPath.last, "Social")
        XCTAssertNotNil(twitter.totp)
        XCTAssertEqual(entries.first { $0.title == "Bank" }?.password, "s3cret!")
    }

    func testKDBX3() throws {
        let db = try KDBXReader.open(data: fixture("v3"), password: "test-password")
        XCTAssertEqual(db.name, "Legacy DB")
        XCTAssertEqual(db.formatVersion, "KDBX 3.1")
        let mail = try XCTUnwrap(db.activeEntries.first { $0.title == "Mail" })
        XCTAssertEqual(mail.password, "first-secret")
        XCTAssertEqual(mail.tags, ["a", "b"])
        XCTAssertNil(mail.expires)
        XCTAssertEqual(mail.attachments.first?.data, Data("hello attachment".utf8))
        XCTAssertEqual(mail.historyCount, 1)
        let vpn = try XCTUnwrap(db.activeEntries.first { $0.title == "VPN" })
        XCTAssertEqual(vpn.password, "second-secret")
        XCTAssertEqual(vpn[field: "PIN"], "1234")
        XCTAssertEqual(vpn.groupPath, ["Root", "Work"])
    }

    func testKDBX3HeaderTamperingIsDetected() throws {
        var data = try fixture("v3")
        // Alter the end-of-header field's payload: it doesn't affect decryption but is covered by <HeaderHash>.
        let commentField: [UInt8] = [0x00, 0x04, 0x00, 0x0D, 0x0A, 0x0D, 0x0A]
        let range = try XCTUnwrap(data.firstRange(of: Data(commentField)))
        data[range.upperBound - 1] = 0x00
        XCTAssertThrowsError(try KDBXReader.open(data: data, password: "test-password")) {
            XCTAssertEqual($0 as? KDBXError, .corrupt("Header checksum mismatch"))
        }
    }

    func testWrongPassword() throws {
        XCTAssertThrowsError(try KDBXReader.open(data: fixture("v4"), password: "nope")) {
            XCTAssertEqual($0 as? KDBXError, .invalidCredentials)
        }
        XCTAssertThrowsError(try KDBXReader.open(data: fixture("v3"), password: "nope")) {
            XCTAssertEqual($0 as? KDBXError, .invalidCredentials)
        }
    }

    func testTOTP() {
        // RFC 6238 test vector (SHA1, 8 digits, T=59)
        let totp = TOTP(secret: Array("12345678901234567890".utf8), digits: 8)
        XCTAssertEqual(totp.code(at: Date(timeIntervalSince1970: 59)), "94287082")
    }

    /// Values read from an untrusted file must never crash the app.
    func testHostileValuesAreClamped() {
        var entry = KDBXEntry(id: UUID())
        entry.fields = [KDBXField(key: "TimeOtp-Secret-Base32", value: "JBSWY3DPEHPK3PXP", isProtected: true),
                        KDBXField(key: "TimeOtp-Period", value: "0", isProtected: false),
                        KDBXField(key: "TimeOtp-Length", value: "999999999", isProtected: false)]
        let totp = try! XCTUnwrap(entry.totp)
        XCTAssertEqual(totp.period, 1)
        XCTAssertEqual(totp.code().count, 10)
        XCTAssertGreaterThan(totp.secondsRemaining(), 0)

        // Int64.min seconds would previously overflow.
        XCTAssertNotNil(XMLDatabaseParser.date(Data([0, 0, 0, 0, 0, 0, 0, 0x80]).base64EncodedString()))
    }

    func testHostileXMLDoesNotCrash() throws {
        let xml = """
        <KeePassFile><Meta><Binaries><Binary ID="-5">AA==</Binary><Binary ID="99999999999">AA==</Binary></Binaries>
        <Entry><String><Key>Title</Key><Value>stray</Value></String></Entry></Meta>
        <Root><Group><Name>R</Name><Entry><Binary><Key>x</Key><Value Ref="-1"/></Binary></Entry></Group></Root></KeePassFile>
        """
        let db = try XMLDatabaseParser.parse(Data(xml.utf8), stream: ChaCha20(key: .init(repeating: 0, count: 32),
                                             nonce: .init(repeating: 0, count: 12)), binaries: [], formatVersion: "test")
        XCTAssertEqual(db.activeEntries.count, 1)
        XCTAssertTrue(db.activeEntries[0].attachments.isEmpty)
    }

    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
}
