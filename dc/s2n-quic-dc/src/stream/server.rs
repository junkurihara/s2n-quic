// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use crate::{credentials::Credentials, msg::recv, packet};
use s2n_codec::{DecoderBufferMut, DecoderError};

pub mod handshake;
pub mod tokio;

#[derive(Debug)]
pub struct InitialPacket {
    pub credentials: Credentials,
    pub stream_id: packet::stream::Id,
    pub source_control_port: u16,
    pub source_stream_port: Option<u16>,
    pub payload_len: usize,
    pub is_zero_offset: bool,
    pub is_retransmission: bool,
    pub is_fin: bool,
}

impl InitialPacket {
    #[inline]
    pub fn peek(recv: &mut recv::Message, tag_len: usize) -> Result<Self, DecoderError> {
        let segment = recv
            .peek_segments()
            .next()
            .ok_or(DecoderError::UnexpectedEof(1))?;

        let decoder = DecoderBufferMut::new(segment);
        // we're just going to assume that all of the packets in this datagram
        // pertain to the same stream
        let (packet, _remaining) = decoder.decode_parameterized(tag_len)?;

        let packet::Packet::Stream(packet) = packet else {
            return Err(DecoderError::InvariantViolation("unexpected packet type"));
        };

        let packet: InitialPacket = packet.into();

        Ok(packet)
    }
}

impl<'a> From<packet::stream::decoder::Packet<'a>> for InitialPacket {
    #[inline]
    fn from(packet: packet::stream::decoder::Packet<'a>) -> Self {
        let credentials = *packet.credentials();
        let stream_id = *packet.stream_id();
        let source_control_port = packet.source_control_port();
        let source_stream_port = packet.source_stream_port();
        let payload_len = packet.payload().len();
        let is_zero_offset = packet.stream_offset().as_u64() == 0;
        let is_retransmission = packet.is_retransmission();
        let is_fin = packet.is_fin();
        Self {
            credentials,
            stream_id,
            source_control_port,
            source_stream_port,
            is_zero_offset,
            payload_len,
            is_retransmission,
            is_fin,
        }
    }
}
