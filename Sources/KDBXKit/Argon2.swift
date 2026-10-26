import Foundation

/// BLAKE2b (RFC 7693), unkeyed, one-shot.
enum Blake2b {
    private static let iv: [UInt64] = [
        0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
        0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179,
    ]
    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    static func hash(_ input: [UInt8], outputLength: Int) -> [UInt8] {
        precondition(outputLength >= 1 && outputLength <= 64)
        var h = iv
        h[0] ^= 0x0101_0000 ^ UInt64(outputLength)

        var counter: UInt64 = 0
        var offset = 0
        repeat {
            let chunk = min(128, input.count - offset)
            let isLast = offset + chunk >= input.count
            var block = [UInt8](repeating: 0, count: 128)
            if chunk > 0 { block.replaceSubrange(0..<chunk, with: input[offset..<offset + chunk]) }
            counter += UInt64(chunk)
            compress(&h, block, counter, isLast)
            offset += chunk
        } while offset < input.count

        var out = [UInt8]()
        out.reserveCapacity(64)
        for word in h { out += [UInt8].le64(word) }
        return Array(out.prefix(outputLength))
    }

    private static func compress(_ h: inout [UInt64], _ block: [UInt8], _ t: UInt64, _ last: Bool) {
        var m = [UInt64](repeating: 0, count: 16)
        for i in 0..<16 {
            var w: UInt64 = 0
            for j in 0..<8 { w |= UInt64(block[i * 8 + j]) << (8 * UInt64(j)) }
            m[i] = w
        }
        var v = h + iv
        v[12] ^= t
        if last { v[14] = ~v[14] }

        func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
            v[a] = v[a] &+ v[b] &+ x; v[d] = (v[d] ^ v[a]).rotr(32)
            v[c] = v[c] &+ v[d];      v[b] = (v[b] ^ v[c]).rotr(24)
            v[a] = v[a] &+ v[b] &+ y; v[d] = (v[d] ^ v[a]).rotr(16)
            v[c] = v[c] &+ v[d];      v[b] = (v[b] ^ v[c]).rotr(63)
        }
        for r in 0..<12 {
            let s = sigma[r % 10]
            g(0, 4, 8, 12, m[s[0]], m[s[1]]); g(1, 5, 9, 13, m[s[2]], m[s[3]])
            g(2, 6, 10, 14, m[s[4]], m[s[5]]); g(3, 7, 11, 15, m[s[6]], m[s[7]])
            g(0, 5, 10, 15, m[s[8]], m[s[9]]); g(1, 6, 11, 12, m[s[10]], m[s[11]])
            g(2, 7, 8, 13, m[s[12]], m[s[13]]); g(3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for i in 0..<8 { h[i] ^= v[i] ^ v[i + 8] }
    }
}

extension UInt64 {
    @inline(__always) func rotr(_ n: UInt64) -> UInt64 { (self >> n) | (self << (64 - n)) }
}

/// Argon2d / Argon2id (versions 0x10 and 0x13), as used by KDBX 4.
public enum Argon2 {
    public enum Variant: UInt32 { case d = 0, id = 2 }

    private static let blockWords = 128 // 1 KiB blocks

    // Upper bounds for parameters read from a database header (KeePassXC's own limits are similar).
    static let maxIterations: UInt64 = 1 << 16
    static let maxMemoryBytes: UInt64 = 4 << 30
    static let maxParallelism: UInt64 = 256

    public static func hash(password: [UInt8], salt: [UInt8], iterations: UInt32, memoryKiB: UInt32,
                            parallelism: UInt32, version: UInt32, variant: Variant,
                            outputLength: Int = 32) throws -> [UInt8] {
        guard parallelism >= 1, iterations >= 1, version == 0x10 || version == 0x13 else {
            throw KDBXError.unsupportedKDF
        }
        let lanes = Int(parallelism)
        let memoryBlocks = max(Int(memoryKiB), 8 * lanes) / (4 * lanes) * (4 * lanes)
        let laneLength = memoryBlocks / lanes
        let segmentLength = laneLength / 4

        // H0
        var h0Input = [UInt8]()
        h0Input += .le32(parallelism) + .le32(UInt32(outputLength)) + .le32(memoryKiB)
        h0Input += .le32(iterations) + .le32(version) + .le32(variant.rawValue)
        h0Input += .le32(UInt32(password.count)) + password
        h0Input += .le32(UInt32(salt.count)) + salt
        h0Input += .le32(0) + .le32(0) // no secret, no associated data
        let h0 = Blake2b.hash(h0Input, outputLength: 64)

        let memory = UnsafeMutablePointer<UInt64>.allocate(capacity: memoryBlocks * blockWords)
        memory.initialize(repeating: 0, count: memoryBlocks * blockWords)
        defer {
            memory.update(repeating: 0, count: memoryBlocks * blockWords)
            memory.deallocate()
        }

        for lane in 0..<lanes {
            for i in 0..<2 {
                let bytes = variableHash(h0 + .le32(UInt32(i)) + .le32(UInt32(lane)), length: 1024)
                let block = memory + (lane * laneLength + i) * blockWords
                for w in 0..<blockWords {
                    var v: UInt64 = 0
                    for j in 0..<8 { v |= UInt64(bytes[w * 8 + j]) << (8 * UInt64(j)) }
                    block[w] = v
                }
            }
        }

        let ctx = FillContext(memory: memory, lanes: lanes, laneLength: laneLength, segmentLength: segmentLength,
                              memoryBlocks: memoryBlocks, passes: Int(iterations), variant: variant, version: version)
        for pass in 0..<Int(iterations) {
            for slice in 0..<4 {
                if lanes == 1 {
                    ctx.fillSegment(pass: pass, lane: 0, slice: slice)
                } else {
                    DispatchQueue.concurrentPerform(iterations: lanes) { lane in
                        ctx.fillSegment(pass: pass, lane: lane, slice: slice)
                    }
                }
            }
        }

        var final = [UInt64](repeating: 0, count: blockWords)
        for lane in 0..<lanes {
            let block = memory + (lane * laneLength + laneLength - 1) * blockWords
            for w in 0..<blockWords { final[w] ^= block[w] }
        }
        var finalBytes = [UInt8]()
        finalBytes.reserveCapacity(1024)
        for w in final { finalBytes += .le64(w) }
        return variableHash(finalBytes, length: outputLength)
    }

    /// H' — variable-length hash built from BLAKE2b.
    static func variableHash(_ input: [UInt8], length: Int) -> [UInt8] {
        let prefixed = [UInt8].le32(UInt32(length)) + input
        if length <= 64 { return Blake2b.hash(prefixed, outputLength: length) }
        var out = [UInt8]()
        out.reserveCapacity(length)
        var v = Blake2b.hash(prefixed, outputLength: 64)
        out += v.prefix(32)
        while length - out.count > 64 {
            v = Blake2b.hash(v, outputLength: 64)
            out += v.prefix(32)
        }
        out += Blake2b.hash(v, outputLength: length - out.count)
        return out
    }

    private final class FillContext: @unchecked Sendable {
        let memory: UnsafeMutablePointer<UInt64>
        let lanes, laneLength, segmentLength, memoryBlocks, passes: Int
        let variant: Variant
        let version: UInt32

        init(memory: UnsafeMutablePointer<UInt64>, lanes: Int, laneLength: Int, segmentLength: Int,
             memoryBlocks: Int, passes: Int, variant: Variant, version: UInt32) {
            self.memory = memory; self.lanes = lanes; self.laneLength = laneLength
            self.segmentLength = segmentLength; self.memoryBlocks = memoryBlocks; self.passes = passes
            self.variant = variant; self.version = version
        }

        func fillSegment(pass: Int, lane: Int, slice: Int) {
            let dataIndependent = variant == .id && pass == 0 && slice < 2

            let scratch = UnsafeMutablePointer<UInt64>.allocate(capacity: 128 * 5)
            scratch.initialize(repeating: 0, count: 128 * 5)
            defer { scratch.deallocate() }
            let zero = scratch, input = scratch + 128, address = scratch + 256, tmp = scratch + 384

            if dataIndependent {
                input[0] = UInt64(pass); input[1] = UInt64(lane); input[2] = UInt64(slice)
                input[3] = UInt64(memoryBlocks); input[4] = UInt64(passes); input[5] = UInt64(variant.rawValue)
            }
            func nextAddresses() {
                input[6] &+= 1
                compress(zero, input, into: address, xorInto: false, tmp: tmp)
                compress(zero, address, into: address, xorInto: false, tmp: tmp)
            }

            var startIndex = 0
            if pass == 0 && slice == 0 {
                startIndex = 2
                if dataIndependent { nextAddresses() }
            }

            var current = lane * laneLength + slice * segmentLength + startIndex
            var previous = current % laneLength == 0 ? current + laneLength - 1 : current - 1

            for index in startIndex..<segmentLength {
                if current % laneLength == 1 { previous = current - 1 }

                let pseudoRandom: UInt64
                if dataIndependent {
                    if index % 128 == 0 { nextAddresses() }
                    pseudoRandom = address[index % 128]
                } else {
                    pseudoRandom = memory[previous * 128]
                }

                var refLane = Int((pseudoRandom >> 32) % UInt64(lanes))
                if pass == 0 && slice == 0 { refLane = lane }
                let refIndex = referenceIndex(pass: pass, slice: slice, index: index,
                                              pseudoRandom: pseudoRandom & 0xFFFF_FFFF, sameLane: refLane == lane)

                let refBlock = memory + (refLane * laneLength + refIndex) * 128
                let xorInto = version == 0x13 && pass > 0
                compress(memory + previous * 128, refBlock, into: memory + current * 128, xorInto: xorInto, tmp: tmp)

                current += 1
                previous += 1
            }
        }

        private func referenceIndex(pass: Int, slice: Int, index: Int, pseudoRandom: UInt64, sameLane: Bool) -> Int {
            var areaSize: Int
            if pass == 0 {
                if slice == 0 {
                    areaSize = index - 1
                } else if sameLane {
                    areaSize = slice * segmentLength + index - 1
                } else {
                    areaSize = slice * segmentLength + (index == 0 ? -1 : 0)
                }
            } else if sameLane {
                areaSize = laneLength - segmentLength + index - 1
            } else {
                areaSize = laneLength - segmentLength + (index == 0 ? -1 : 0)
            }
            var relative = pseudoRandom
            relative = (relative &* relative) >> 32
            relative = UInt64(areaSize) - 1 - ((UInt64(areaSize) &* relative) >> 32)
            let start = pass != 0 ? (slice == 3 ? 0 : (slice + 1) * segmentLength) : 0
            return (start + Int(relative)) % laneLength
        }

        /// G(X, Y): R = X ⊕ Y, apply P row- then column-wise, output = P(R) ⊕ R (⊕ old block for v1.3 passes > 0).
        @inline(__always)
        private func compress(_ x: UnsafeMutablePointer<UInt64>, _ y: UnsafeMutablePointer<UInt64>,
                              into out: UnsafeMutablePointer<UInt64>, xorInto: Bool, tmp: UnsafeMutablePointer<UInt64>) {
            let r = tmp + 128
            for i in 0..<128 { r[i] = x[i] ^ y[i]; tmp[i] = r[i] }
            if xorInto { for i in 0..<128 { tmp[i] ^= out[i] } }

            for i in 0..<8 {
                let b = 16 * i
                permute(r, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7,
                        b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15)
            }
            for i in 0..<8 {
                let b = 2 * i
                permute(r, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49,
                        b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113)
            }
            for i in 0..<128 { out[i] = tmp[i] ^ r[i] }
        }

        @inline(__always)
        private func permute(_ v: UnsafeMutablePointer<UInt64>, _ i0: Int, _ i1: Int, _ i2: Int, _ i3: Int,
                             _ i4: Int, _ i5: Int, _ i6: Int, _ i7: Int, _ i8: Int, _ i9: Int, _ i10: Int,
                             _ i11: Int, _ i12: Int, _ i13: Int, _ i14: Int, _ i15: Int) {
            gb(v, i0, i4, i8, i12); gb(v, i1, i5, i9, i13); gb(v, i2, i6, i10, i14); gb(v, i3, i7, i11, i15)
            gb(v, i0, i5, i10, i15); gb(v, i1, i6, i11, i12); gb(v, i2, i7, i8, i13); gb(v, i3, i4, i9, i14)
        }

        @inline(__always)
        private func gb(_ v: UnsafeMutablePointer<UInt64>, _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            @inline(__always) func fBlaMka(_ x: UInt64, _ y: UInt64) -> UInt64 {
                x &+ y &+ 2 &* (x & 0xFFFF_FFFF) &* (y & 0xFFFF_FFFF)
            }
            v[a] = fBlaMka(v[a], v[b]); v[d] = (v[d] ^ v[a]).rotr(32)
            v[c] = fBlaMka(v[c], v[d]); v[b] = (v[b] ^ v[c]).rotr(24)
            v[a] = fBlaMka(v[a], v[b]); v[d] = (v[d] ^ v[a]).rotr(16)
            v[c] = fBlaMka(v[c], v[d]); v[b] = (v[b] ^ v[c]).rotr(63)
        }
    }
}
