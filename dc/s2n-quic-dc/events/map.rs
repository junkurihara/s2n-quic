// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[event("path_secret_map:initialized")]
#[subject(endpoint)]
struct PathSecretMapInitialized {
    /// The capacity of the path secret map
    capacity: usize,
}

#[event("path_secret_map:uninitialized")]
#[subject(endpoint)]
struct PathSecretMapUninitialized {
    /// The capacity of the path secret map
    capacity: usize,

    /// The number of entries in the map
    entries: usize,
}

#[event("path_secret_map:background_handshake_requested")]
#[subject(endpoint)]
/// Emitted when a background handshake is requested
struct PathSecretMapBackgroundHandshakeRequested<'a> {
    peer_address: SocketAddress<'a>,
}

#[event("path_secret_map:entry_replaced")]
#[subject(endpoint)]
/// Emitted when the entry is inserted into the path secret map
struct PathSecretMapEntryInserted<'a> {
    peer_address: SocketAddress<'a>,

    credential_id: &'a [u8],
}

#[event("path_secret_map:entry_replaced")]
#[subject(endpoint)]
/// Emitted when the entry is considered ready for use
struct PathSecretMapEntryReady<'a> {
    peer_address: SocketAddress<'a>,

    credential_id: &'a [u8],
}

#[event("path_secret_map:entry_replaced")]
#[subject(endpoint)]
/// Emitted when an entry is replaced by a new one for the same `peer_address`
struct PathSecretMapEntryReplaced<'a> {
    peer_address: SocketAddress<'a>,

    new_credential_id: &'a [u8],

    previous_credential_id: &'a [u8],
}

#[event("path_secret_map:unknown_path_secret_packet_sent")]
#[subject(endpoint)]
/// Emitted when an UnknownPathSecret packet was sent
struct UnknownPathSecretPacketSent<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}

#[event("path_secret_map:unknown_path_secret_packet_received")]
#[subject(endpoint)]
/// Emitted when an UnknownPathSecret packet was received
struct UnknownPathSecretPacketReceived<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}

#[event("path_secret_map:unknown_path_secret_packet_accepted")]
#[subject(endpoint)]
/// Emitted when an UnknownPathSecret packet was authentic and processed
struct UnknownPathSecretPacketAccepted<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}

#[event("path_secret_map:unknown_path_secret_packet_rejected")]
#[subject(endpoint)]
/// Emitted when an UnknownPathSecret packet was rejected as invalid
struct UnknownPathSecretPacketRejected<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}

#[event("path_secret_map:unknown_path_secret_packet_dropped")]
#[subject(endpoint)]
/// Emitted when an UnknownPathSecret packet was dropped due to a missing entry
struct UnknownPathSecretPacketDropped<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}

#[event("path_secret_map:replay_definitely_detected")]
#[subject(endpoint)]
/// Emitted when credential replay was definitely detected
struct ReplayDefinitelyDetected<'a> {
    credential_id: &'a [u8],
    key_id: u64,
}

#[event("path_secret_map:replay_potentially_detected")]
#[subject(endpoint)]
/// Emitted when credential replay was potentially detected, but could not be verified
/// due to a limiting tracking window
struct ReplayPotentiallyDetected<'a> {
    credential_id: &'a [u8],
    key_id: u64,
    gap: u64,
}

#[event("path_secret_map:replay_detected_packet_sent")]
#[subject(endpoint)]
/// Emitted when an ReplayDetected packet was sent
struct ReplayDetectedPacketSent<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}

#[event("path_secret_map:replay_detected_packet_received")]
#[subject(endpoint)]
/// Emitted when an ReplayDetected packet was received
struct ReplayDetectedPacketReceived<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}

#[event("path_secret_map:replay_detected_packet_accepted")]
#[subject(endpoint)]
/// Emitted when an StaleKey packet was authentic and processed
struct ReplayDetectedPacketAccepted<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
    key_id: u64,
}

#[event("path_secret_map:replay_detected_packet_rejected")]
#[subject(endpoint)]
/// Emitted when an ReplayDetected packet was rejected as invalid
struct ReplayDetectedPacketRejected<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}

#[event("path_secret_map:replay_detected_packet_dropped")]
#[subject(endpoint)]
/// Emitted when an ReplayDetected packet was dropped due to a missing entry
struct ReplayDetectedPacketDropped<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}

#[event("path_secret_map:stale_key_packet_sent")]
#[subject(endpoint)]
/// Emitted when an StaleKey packet was sent
struct StaleKeyPacketSent<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}

#[event("path_secret_map:stale_key_packet_received")]
#[subject(endpoint)]
/// Emitted when an StaleKey packet was received
struct StaleKeyPacketReceived<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}

#[event("path_secret_map:stale_key_packet_accepted")]
#[subject(endpoint)]
/// Emitted when an StaleKey packet was authentic and processed
struct StaleKeyPacketAccepted<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}

#[event("path_secret_map:stale_key_packet_rejected")]
#[subject(endpoint)]
/// Emitted when an StaleKey packet was rejected as invalid
struct StaleKeyPacketRejected<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}

#[event("path_secret_map:stale_key_packet_dropped")]
#[subject(endpoint)]
/// Emitted when an StaleKey packet was dropped due to a missing entry
struct StaleKeyPacketDropped<'a> {
    peer_address: SocketAddress<'a>,
    credential_id: &'a [u8],
}
