//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
//
// Modificado por SuperPartner el 9 de noviembre de 2026 (SuperPartnerDev/swift-nio-ssh): el parser
// sabe si es servidor, para leer la versión del peer como pide su papel (Apple #153).
//

import NIOCore

extension SSHConnectionStateMachine {
    /// The state of a state machine that has sent its version header.
    struct SentVersionState {
        /// The role of the connection
        let role: SSHConnectionRole

        /// The packet parser.
        var parser: SSHPacketParser

        /// The packet serializer used by this state machine.
        var serializer: SSHPacketSerializer

        let connectionAttributes: SSHConnectionStateMachine.Attributes
        
        private let allocator: ByteBufferAllocator

        init(idleState state: IdleState, allocator: ByteBufferAllocator, maximumPacketSize: Int) {
            self.role = state.role
            self.serializer = state.serializer

            self.parser = SSHPacketParser(allocator: allocator, maximumPacketSize: maximumPacketSize, isServer: state.role.isServer)
            self.allocator = allocator
            self.connectionAttributes = state.connectionAttributes
        }
    }
}

extension SSHConnectionStateMachine.SentVersionState: AcceptsVersionMessages {}
