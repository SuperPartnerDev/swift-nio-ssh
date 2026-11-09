//===----------------------------------------------------------------------===//
//
// This source file is part of the SuperPartnerDev/swift-nio-ssh fork of the
// SwiftNIO open source project.
//
// Copyright (c) 2026 SuperPartner. Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
@testable import NIOSSH
import XCTest

/// F6 of the 22 Sep 2026 security review: a certificate whose signature key is another certificate, nested many
/// times, made the parser recurse once per level before any check, during key exchange (before authentication).
final class NestedCertificateTests: XCTestCase {
    /// An ssh-ed25519-cert-v01 host certificate whose signature key is the next one, `depth` times, ending in a
    /// plain ssh-ed25519 key. Written front to back with the lengths computed first, so building it is linear.
    private func nestedCertificate(depth: Int) -> ByteBuffer {
        let certPrefix = Array("ssh-ed25519-cert-v01@openssh.com".utf8)
        let keyBytes = [UInt8](repeating: 7, count: 32)
        var header = ByteBuffer()
        header.writeSSHString(certPrefix)
        header.writeSSHString([UInt8]())        // nonce
        header.writeSSHString(keyBytes)          // ed25519 public key, without its prefix
        header.writeInteger(UInt64(1))           // serial
        header.writeInteger(UInt32(2))           // type: host
        header.writeSSHString([UInt8]())        // key id
        header.writeSSHString([UInt8]())        // principals
        header.writeInteger(UInt64(0))           // valid after
        header.writeInteger(UInt64.max)          // valid before
        header.writeSSHString([UInt8]())        // critical options
        header.writeSSHString([UInt8]())        // extensions
        header.writeSSHString([UInt8]())        // reserved
        var innermost = ByteBuffer()
        innermost.writeSSHString(Array("ssh-ed25519".utf8))
        innermost.writeSSHString(keyBytes)
        let trailer = 4                          // empty signature string after each signature key

        // lengths[k] = size of the key blob at nesting level k (0 = innermost plain key).
        var lengths = [innermost.readableBytes]
        for _ in 0..<depth { lengths.append(header.readableBytes + 4 + lengths.last! + trailer) }

        var buffer = ByteBuffer()
        buffer.reserveCapacity(lengths.last!)
        for level in stride(from: depth, to: 0, by: -1) {
            buffer.writeImmutableBuffer(header)
            buffer.writeInteger(UInt32(lengths[level - 1]))   // the signature key string that follows
        }
        buffer.writeImmutableBuffer(innermost)
        for _ in 0..<depth { buffer.writeInteger(UInt32(0)) } // each level's empty signature
        return buffer
    }

    func testCertificateSignedByCertificateIsRejected() {
        var buffer = self.nestedCertificate(depth: 2)
        XCTAssertThrowsError(try buffer.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidCertificate)
        }
    }

    /// Without the check before reading the signature key this recursed 100 000 levels deep and the process
    /// died on the stack; now the first level already throws.
    func testDeeplyNestedCertificatesAreRejectedWithoutRecursing() {
        var buffer = self.nestedCertificate(depth: 100_000)
        XCTAssertThrowsError(try buffer.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidCertificate)
        }
    }
}
