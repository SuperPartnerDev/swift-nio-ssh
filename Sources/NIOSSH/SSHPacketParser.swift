//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
//
// Modificado por SuperPartner el 23 de septiembre de 2026 (SuperPartnerDev/swift-nio-ssh):
// decryptLength rechaza una longitud que desborde al sumar macBytes (F1; Apple #244) y
// readVersion acota el identificador de versión a 255 bytes (RFC 4253 §4.2; Apple #244).
// Modificado el 9 de noviembre de 2026: en el cliente, readVersion devuelve solo la línea de versión,
// sin las líneas que el servidor manda antes (RFC 4253 §4.2 y §8; Apple #153); un paquete cifrado se
// acepta hasta el tamaño de canal anunciado más 1024 bytes (RFC 4253 §6; Apple #245) y uno sin
// cifrar hasta 256 KiB (Apple #244).
//

import NIOCore

struct SSHPacketParser {
    enum State {
        case initialized
        case cleartextWaitingForLength
        case cleartextWaitingForBytes(UInt32)
        case encryptedWaitingForLength(NIOSSHTransportProtection)
        case encryptedWaitingForBytes(UInt32, NIOSSHTransportProtection)
    }

    private var buffer: ByteBuffer
    private var state: State
    private var sequenceNumber: UInt32 = 0
    private let maximumPacketSize: Int

    /// Tope de un paquete cifrado: el tamaño de canal anunciado más el margen de Apple (#245).
    private var maximumEncryptedPacketLength: UInt32 { UInt32(self.maximumPacketSize) + 1024 }

    /// Tope de un paquete sin cifrar (Apple #244).
    static let maximumPlaintextPacketLength: UInt32 = 256 * 1024
    internal static let defaultMaximumPacketSize = 1 << 17

    /// Testing only: the number of bytes we can discard from this buffer.
    internal var _discardableBytes: Int {
        self.buffer.readerIndex
    }

    /// En el servidor, las líneas previas a la versión siguen llegando con ella y la validación del banner las
    /// rechaza: solo el servidor puede mandarlas (RFC 4253 §4.2). Apple #153 separa los dos papeles igual.
    private let isServer: Bool

    init(allocator: ByteBufferAllocator, maximumPacketSize: Int = defaultMaximumPacketSize, isServer: Bool = false) {
        self.isServer = isServer
        // Assert that users don't provide a packet size lower than allowed by spec
        precondition(maximumPacketSize >= 32768, "Maximum Packet Size is below minimum requirement as specified by RFC 4254")
        precondition(maximumPacketSize <= (1 << 24), "Maximum Packet Size is set abnormally high")

        self.buffer = allocator.buffer(capacity: 0)
        self.state = .initialized
        self.maximumPacketSize = maximumPacketSize
    }

    mutating func append(bytes: inout ByteBuffer) {
        self.buffer.writeBuffer(&bytes)
    }

    /// Encryption schemes can be added to a packet parser whenever encryption is negotiated.
    /// They must be added monotonically, and may only be added once, while the parser is in an
    /// idle state.
    mutating func addEncryption(_ protection: NIOSSHTransportProtection) {
        switch self.state {
        case .cleartextWaitingForLength:
            self.state = .encryptedWaitingForLength(protection)
        case .encryptedWaitingForLength:
            self.state = .encryptedWaitingForLength(protection)
        case .cleartextWaitingForBytes, .initialized, .encryptedWaitingForBytes:
            preconditionFailure("Adding encryption in invalid state: \(self.state)")
        }
    }

    mutating func nextPacket() throws -> SSHMessage? {
        // This parser has a slightly strange strategy: we leave the packet length field in the buffer until we're done.
        // This is necessary because some transport protection schemes need the length field for MACing purposes, and can
        // benefit from us maintaining the state instead of having to do it themselves.
        defer {
            self.reclaimBytes()
        }

        switch self.state {
        case .initialized:
            if let version = try self.readVersion() {
                self.state = .cleartextWaitingForLength
                return .version(version)
            }
            return nil
        case .cleartextWaitingForLength:
            if let length = self.buffer.getInteger(at: self.buffer.readerIndex, as: UInt32.self) {
                // Sin cifrar solo viajan el intercambio de claves y la versión: tope fijo de 256 KiB,
                // como Apple (`maximumPlaintextPacketLength`, #244).
                if length > Self.maximumPlaintextPacketLength {
                    throw NIOSSHError.invalidEncryptedPacketLength
                }

                if let message = try self.parsePlaintext(length: length) {
                    self.state = .cleartextWaitingForLength
                    self.sequenceNumber = self.sequenceNumber &+ 1
                    return message
                }
                self.state = .cleartextWaitingForBytes(length)
                return nil
            }
            return nil
        case .cleartextWaitingForBytes(let length):
            if let message = try self.parsePlaintext(length: length) {
                self.state = .cleartextWaitingForLength
                self.sequenceNumber = self.sequenceNumber &+ 1
                return message
            }
            return nil
        case .encryptedWaitingForLength(let protection):
            guard let length = try self.decryptLength(protection: protection) else {
                return nil
            }

            if let message = try self.parseCiphertext(length: length, protection: protection) {
                self.state = .encryptedWaitingForLength(protection)
                self.sequenceNumber = self.sequenceNumber &+ 1
                return message
            }
            self.state = .encryptedWaitingForBytes(length, protection)
            return nil
        case .encryptedWaitingForBytes(let length, let protection):
            if let message = try self.parseCiphertext(length: length, protection: protection) {
                self.state = .encryptedWaitingForLength(protection)
                self.sequenceNumber = self.sequenceNumber &+ 1
                return message
            }
            return nil
        }
    }

    private mutating func reclaimBytes() {
        if self.buffer.readerIndex > 1024, self.buffer.readerIndex > (self.buffer.readableBytes / 2) {
            self.buffer.discardReadBytes()
        }
    }

    internal static let maximumAllowedVersionSize = 4096

    /// RFC 4253 §4.2: el identificador de versión ("SSH-...") no pasa de 255 bytes, CR y LF
    /// incluidos. Las líneas de preámbulo siguen acotadas en total por maximumAllowedVersionSize.
    internal static let maximumVersionLineLength = 255
    private mutating func readVersion() throws -> String? {
        // Looking for a complete SSH version string, potentially with pre-lines
        let slice = self.buffer.readableBytesView

        // Prevent the consumed bytes for a version from exceeding the defined maximum allowed size
        // In practice, if SSH version packets come anywhere near this it's already likely an attack
        // More data cannot be blindly regarded as malicious though, since this might contain multiple packets
        let maxIndex = slice.index(slice.startIndex, offsetBy: min(slice.count, Self.maximumAllowedVersionSize))

        var lastLineEndIndex: ByteBufferView.Index?
        
        for index in slice.startIndex ..< slice.endIndex {
            if index > maxIndex {
                // Does not account for `CRLF`
                throw NIOSSHError.excessiveVersionLength
            }

            if slice[index] == 10 { // Found a line ending
                let lineStartIndex = lastLineEndIndex?.advanced(by: 1) ?? slice.startIndex
                let lineSlice = slice[lineStartIndex..<index]
                
                // Check if this line looks like an SSH version (any SSH version, not just 2.0)
                if lineSlice.count >= 4 && lineSlice.starts(with: "SSH-".utf8) {
                    // El identificador lo elige el peer: se acota a los 255 bytes del RFC (lineSlice
                    // incluye el CR si lo hay; el +1 es el LF). Límite que Apple añadió en #244.
                    guard lineSlice.count + 1 <= Self.maximumVersionLineLength else {
                        throw NIOSSHError.excessiveVersionLength
                    }
                    // En el cliente, solo la línea de versión: es la que entra al hash del intercambio de claves (RFC 4253
                    // §8). Las líneas previas del servidor (§4.2) se consumen y se ignoran; con ellas dentro el
                    // hash no coincidía y la conexión fallaba al verificar la firma del host. Apple #153.
                    var version = String(decoding: self.isServer ? slice[slice.startIndex..<index] : lineSlice, as: UTF8.self)
                    // read including \n
                    self.buffer.moveReaderIndex(forwardBy: slice.startIndex.distance(to: index).advanced(by: 1))
                    // Remove the trailing \r if present (but keep \n removal logic for consistency)
                    if version.last == "\r" {
                        version.removeLast()
                    }
                    return version
                }
                
                lastLineEndIndex = index
            }
        }

        return nil
    }

    private mutating func decryptLength(protection: NIOSSHTransportProtection) throws -> UInt32? {
        let blockSize = protection.cipherBlockSize
        guard self.buffer.readableBytes >= blockSize else {
            return nil
        }

        try protection.decryptFirstBlock(&self.buffer)

        // This force unwrap is safe because we must have a block size, and a block size is always going to be more than 4 bytes.
        let packetLength = self.buffer.getInteger(at: self.buffer.readerIndex, as: UInt32.self)!

        // La longitud la manda el peer y, con AES-GCM, va en claro y sin autenticar: se suma sin
        // abortar, porque el + de Swift mataba el proceso con 0xFFFFFFF0 o más antes de llegar
        // a la comprobación de maximumPacketSize (F1 de la revisión del 22 sep 2026; el mismo
        // guard que Apple añadió en #244).
        // El tope es el tamaño de canal que anunciamos más 1024 bytes para cabeceras y relleno
        // (RFC 4253 §6), como Apple (`maximumEncryptedPacketLength`, #245): un paquete de datos con
        // la carga máxima anunciada es válido y antes se rechazaba.
        let (decryptedLength, overflow) = packetLength.addingReportingOverflow(UInt32(protection.macBytes))
        if overflow || packetLength > self.maximumEncryptedPacketLength {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        return decryptedLength
    }

    private mutating func parsePlaintext(length: UInt32) throws -> SSHMessage? {
        try self.buffer.rewindReaderOnError { buffer in
            guard var buffer = buffer.readSlice(length: Int(length) + MemoryLayout<UInt32>.size) else {
                return nil
            }

            // We have enough length. Skip over the frame length now.
            buffer.moveReaderIndex(forwardBy: MemoryLayout<UInt32>.size)

            var content = try buffer.sliceContentFromPadding()
            guard let message = try content.readSSHMessage(), content.readableBytes == 0, buffer.readableBytes == 0 else {
                // Throw this error if the content wasn't exactly the right length for the message.
                throw NIOSSHError.invalidPacketFormat
            }

            return message
        }
    }

    private mutating func parseCiphertext(length: UInt32, protection: NIOSSHTransportProtection) throws -> SSHMessage? {
        try self.buffer.rewindReaderOnError { buffer in
            guard var buffer = buffer.readSlice(length: Int(length) + MemoryLayout<UInt32>.size) else {
                return nil
            }

            var content = try protection.decryptAndVerifyRemainingPacket(&buffer, sequenceNumber: sequenceNumber)
            guard let message = try content.readSSHMessage(), content.readableBytes == 0, buffer.readableBytes == 0 else {
                // Throw this error if the content wasn't exactly the right length for the message.
                throw NIOSSHError.invalidPacketFormat
            }

            return message
        }
    }
}

private extension ByteBuffer {
    /// Given a ByteBuffer that is exactly the size of a packet with padding (i.e. the padding byte is first),
    /// slices out the part of the packet that is content and returns it, while moving the reader index over the entire
    /// packet.
    mutating func sliceContentFromPadding() throws -> ByteBuffer {
        guard let paddingLength = self.readInteger(as: UInt8.self) else {
            throw NIOSSHError.insufficientPadding
        }

        guard let contentSlice = self.readSlice(length: self.readableBytes - Int(paddingLength)) else {
            throw NIOSSHError.excessPadding
        }

        guard self.readerIndex + Int(paddingLength) == self.writerIndex else {
            throw NIOSSHError.invalidPacketFormat
        }

        self.moveReaderIndex(forwardBy: Int(paddingLength))

        return contentSlice
    }
}
