// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// DO NOT MODIFY THIS FILE
// This file was generated with the `s2n-quic-events` crate and any required
// changes should be made there.

use crate::event::{
    self, api,
    metrics::aggregate::{
        info::{self, Str},
        AsVariant, BoolRecorder, Info, Metric, NominalRecorder, Recorder, Registry, Units,
    },
};
use alloc::{boxed::Box, vec::Vec};
static INFO: &[Info; 161usize] = &[
    info::Builder {
        id: 0usize,
        name: Str::new("application_protocol_information\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 1usize,
        name: Str::new("server_name_information\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 2usize,
        name: Str::new("packet_skipped\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 3usize,
        name: Str::new("packet_sent\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 4usize,
        name: Str::new("packet_sent.kind\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 5usize,
        name: Str::new("packet_sent.bytes.total\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 6usize,
        name: Str::new("packet_sent.bytes\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 7usize,
        name: Str::new("packet_received\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 8usize,
        name: Str::new("packet_received.kind\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 9usize,
        name: Str::new("active_path_updated\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 10usize,
        name: Str::new("path_created\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 11usize,
        name: Str::new("frame_sent\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 12usize,
        name: Str::new("frame_sent.packet\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 13usize,
        name: Str::new("frame_sent.frame\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 14usize,
        name: Str::new("frame_received\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 15usize,
        name: Str::new("frame_received.packet\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 16usize,
        name: Str::new("frame_received.frame\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 17usize,
        name: Str::new("connection_close_frame_received\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 18usize,
        name: Str::new("connection_close_frame_received.packet\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 19usize,
        name: Str::new("packet_lost\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 20usize,
        name: Str::new("packet_lost.kind\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 21usize,
        name: Str::new("packet_lost.bytes.total\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 22usize,
        name: Str::new("packet_lost.bytes\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 23usize,
        name: Str::new("packet_lost.is_mtu_probe\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 24usize,
        name: Str::new("recovery_metrics\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 25usize,
        name: Str::new("recovery_metrics.min_rtt\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 26usize,
        name: Str::new("recovery_metrics.smoothed_rtt\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 27usize,
        name: Str::new("recovery_metrics.latest_rtt\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 28usize,
        name: Str::new("recovery_metrics.rtt_variance\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 29usize,
        name: Str::new("recovery_metrics.max_ack_delay\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 30usize,
        name: Str::new("recovery_metrics.pto_count\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 31usize,
        name: Str::new("recovery_metrics.congestion_window\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 32usize,
        name: Str::new("recovery_metrics.bytes_in_flight\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 33usize,
        name: Str::new("recovery_metrics.congestion_limited\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 34usize,
        name: Str::new("congestion\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 35usize,
        name: Str::new("congestion.source\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 36usize,
        name: Str::new("rx_ack_range_dropped\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 37usize,
        name: Str::new("ack_range_received\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 38usize,
        name: Str::new("ack_range_received.packet\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 39usize,
        name: Str::new("ack_range_sent\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 40usize,
        name: Str::new("ack_range_sent.packet\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 41usize,
        name: Str::new("packet_dropped\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 42usize,
        name: Str::new("packet_dropped.reason\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 43usize,
        name: Str::new("key_update\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 44usize,
        name: Str::new("key_update.key_type\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 45usize,
        name: Str::new("key_update.cipher_suite\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 46usize,
        name: Str::new("key_space_discarded\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 47usize,
        name: Str::new("key_space_discarded.initial.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 48usize,
        name: Str::new("key_space_discarded.handshake.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 49usize,
        name: Str::new("key_space_discarded.one_rtt.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 50usize,
        name: Str::new("key_space_discarded.space\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 51usize,
        name: Str::new("connection_started\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 52usize,
        name: Str::new("duplicate_packet\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 53usize,
        name: Str::new("duplicate_packet.kind\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 54usize,
        name: Str::new("duplicate_packet.error\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 55usize,
        name: Str::new("transport_parameters_received\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 56usize,
        name: Str::new("transport_parameters_received.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 57usize,
        name: Str::new("datagram_sent\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 58usize,
        name: Str::new("datagram_sent.bytes.total\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 59usize,
        name: Str::new("datagram_sent.bytes\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 60usize,
        name: Str::new("datagram_sent.gso_offset\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 61usize,
        name: Str::new("datagram_received\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 62usize,
        name: Str::new("datagram_received.bytes.total\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 63usize,
        name: Str::new("datagram_received.bytes\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 64usize,
        name: Str::new("datagram_dropped\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 65usize,
        name: Str::new("datagram_dropped.bytes.total\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 66usize,
        name: Str::new("datagram_dropped.bytes\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 67usize,
        name: Str::new("datagram_dropped.reason\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 68usize,
        name: Str::new("connection_id_updated\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 69usize,
        name: Str::new("ecn_state_changed\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 70usize,
        name: Str::new("ecn_state_changed.state\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 71usize,
        name: Str::new("connection_migration_denied\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 72usize,
        name: Str::new("connection_migration_denied.reason\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 73usize,
        name: Str::new("handshake_status_updated\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 74usize,
        name: Str::new("handshake_status_updated.complete.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 75usize,
        name: Str::new("handshake_status_updated.confirmed.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 76usize,
        name: Str::new("handshake_status_updated.handshake_done_acked.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 77usize,
        name: Str::new("handshake_status_updated.status\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 78usize,
        name: Str::new("tls_exporter_ready\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 79usize,
        name: Str::new("path_challenge_updated\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 80usize,
        name: Str::new("path_challenge_updated.status\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 81usize,
        name: Str::new("tls_client_hello\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 82usize,
        name: Str::new("tls_client_hello.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 83usize,
        name: Str::new("tls_server_hello\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 84usize,
        name: Str::new("tls_server_hello.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 85usize,
        name: Str::new("rx_stream_progress\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 86usize,
        name: Str::new("rx_stream_progress.bytes.total\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 87usize,
        name: Str::new("rx_stream_progress.bytes\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 88usize,
        name: Str::new("tx_stream_progress\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 89usize,
        name: Str::new("tx_stream_progress.bytes.total\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 90usize,
        name: Str::new("tx_stream_progress.bytes\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 91usize,
        name: Str::new("keep_alive_timer_expired\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 92usize,
        name: Str::new("mtu_updated\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 93usize,
        name: Str::new("mtu_updated.mtu\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 94usize,
        name: Str::new("mtu_updated.cause\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 95usize,
        name: Str::new("mtu_updated.search_complete\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 96usize,
        name: Str::new("slow_start_exited\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 97usize,
        name: Str::new("slow_start_exited.cause\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 98usize,
        name: Str::new("slow_start_exited.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 99usize,
        name: Str::new("slow_start_exited.congestion_window\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 100usize,
        name: Str::new("delivery_rate_sampled\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 101usize,
        name: Str::new("pacing_rate_updated\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 102usize,
        name: Str::new("pacing_rate_updated.bytes_per_second\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 103usize,
        name: Str::new("pacing_rate_updated.burst_size\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 104usize,
        name: Str::new("pacing_rate_updated.pacing_gain\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 105usize,
        name: Str::new("bbr_state_changed\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 106usize,
        name: Str::new("bbr_state_changed.state\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 107usize,
        name: Str::new("dc_state_changed\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 108usize,
        name: Str::new("dc_state_changed.version_negotiated.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 109usize,
        name: Str::new("dc_state_changed.no_version_negotiated.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 110usize,
        name: Str::new("dc_state_changed.path_secrets.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 111usize,
        name: Str::new("dc_state_changed.complete.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 112usize,
        name: Str::new("dc_state_changed.state\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 113usize,
        name: Str::new("connection_closed\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 114usize,
        name: Str::new("connection_closed.latency\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 115usize,
        name: Str::new("connection_closed.error\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 116usize,
        name: Str::new("version_information\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 117usize,
        name: Str::new("endpoint_packet_sent\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 118usize,
        name: Str::new("endpoint_packet_received\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 119usize,
        name: Str::new("endpoint_datagram_sent\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 120usize,
        name: Str::new("endpoint_datagram_sent.bytes\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 121usize,
        name: Str::new("endpoint_datagram_sent.bytes.total\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 122usize,
        name: Str::new("endpoint_datagram_sent.gso_offset\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 123usize,
        name: Str::new("endpoint_datagram_received\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 124usize,
        name: Str::new("endpoint_datagram_received.bytes\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 125usize,
        name: Str::new("endpoint_datagram_received.bytes.total\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 126usize,
        name: Str::new("endpoint_datagram_dropped\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 127usize,
        name: Str::new("endpoint_datagram_dropped.bytes\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 128usize,
        name: Str::new("endpoint_datagram_dropped.bytes.total\0"),
        units: Units::Bytes,
    }
    .build(),
    info::Builder {
        id: 129usize,
        name: Str::new("endpoint_datagram_dropped.reason\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 130usize,
        name: Str::new("endpoint_connection_attempt_failed\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 131usize,
        name: Str::new("endpoint_connection_attempt_failed.error\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 132usize,
        name: Str::new("platform_tx\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 133usize,
        name: Str::new("platform_tx.packets.total\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 134usize,
        name: Str::new("platform_tx.packets\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 135usize,
        name: Str::new("platform_tx.syscalls.total\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 136usize,
        name: Str::new("platform_tx.syscalls\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 137usize,
        name: Str::new("platform_tx.syscalls.blocked.total\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 138usize,
        name: Str::new("platform_tx.syscalls.blocked\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 139usize,
        name: Str::new("platform_tx.errors.total\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 140usize,
        name: Str::new("platform_tx.errors\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 141usize,
        name: Str::new("platform_tx.errors.dropped.total\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 142usize,
        name: Str::new("platform_tx.errors.dropped\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 143usize,
        name: Str::new("platform_tx_error\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 144usize,
        name: Str::new("platform_rx\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 145usize,
        name: Str::new("platform_rx.packets.total\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 146usize,
        name: Str::new("platform_rx.packets\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 147usize,
        name: Str::new("platform_rx.syscalls.total\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 148usize,
        name: Str::new("platform_rx.syscalls\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 149usize,
        name: Str::new("platform_rx.syscalls.blocked.total\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 150usize,
        name: Str::new("platform_rx.syscalls.blocked\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 151usize,
        name: Str::new("platform_rx.errors.total\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 152usize,
        name: Str::new("platform_rx.errors\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 153usize,
        name: Str::new("platform_rx.errors.dropped.total\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 154usize,
        name: Str::new("platform_rx.errors.dropped\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 155usize,
        name: Str::new("platform_rx_error\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 156usize,
        name: Str::new("platform_feature_configured\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 157usize,
        name: Str::new("platform_event_loop_wakeup\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 158usize,
        name: Str::new("platform_event_loop_sleep\0"),
        units: Units::None,
    }
    .build(),
    info::Builder {
        id: 159usize,
        name: Str::new("platform_event_loop_sleep.processing_duration\0"),
        units: Units::Duration,
    }
    .build(),
    info::Builder {
        id: 160usize,
        name: Str::new("platform_event_loop_started\0"),
        units: Units::None,
    }
    .build(),
];
#[derive(Debug)]
#[allow(dead_code)]
pub struct ConnectionContext {
    start_time: crate::event::Timestamp,
}
pub struct Subscriber<R: Registry> {
    #[allow(dead_code)]
    counters: Box<[R::Counter; 75usize]>,
    #[allow(dead_code)]
    bool_counters: Box<[R::BoolCounter; 3usize]>,
    #[allow(dead_code)]
    nominal_counters: Box<[R::NominalCounter]>,
    #[allow(dead_code)]
    nominal_counter_offsets: Box<[usize; 29usize]>,
    #[allow(dead_code)]
    measures: Box<[R::Measure; 38usize]>,
    #[allow(dead_code)]
    gauges: Box<[R::Gauge; 0usize]>,
    #[allow(dead_code)]
    timers: Box<[R::Timer; 15usize]>,
    #[allow(dead_code)]
    nominal_timers: Box<[R::NominalTimer]>,
    #[allow(dead_code)]
    nominal_timer_offsets: Box<[usize; 1usize]>,
    #[allow(dead_code)]
    registry: R,
}
impl<R: Registry + Default> Default for Subscriber<R> {
    fn default() -> Self {
        Self::new(R::default())
    }
}
impl<R: Registry> Subscriber<R> {
    #[doc = r" Creates a new subscriber with the given registry"]
    #[doc = r""]
    #[doc = r" # Note"]
    #[doc = r""]
    #[doc = r" All of the recorders are registered on initialization and cached for the lifetime"]
    #[doc = r" of the subscriber."]
    #[allow(unused_mut)]
    #[inline]
    pub fn new(registry: R) -> Self {
        let mut counters = Vec::with_capacity(75usize);
        let mut bool_counters = Vec::with_capacity(3usize);
        let mut nominal_counters = Vec::with_capacity(29usize);
        let mut nominal_counter_offsets = Vec::with_capacity(29usize);
        let mut measures = Vec::with_capacity(38usize);
        let mut gauges = Vec::with_capacity(0usize);
        let mut timers = Vec::with_capacity(15usize);
        let mut nominal_timers = Vec::with_capacity(1usize);
        let mut nominal_timer_offsets = Vec::with_capacity(1usize);
        counters.push(registry.register_counter(&INFO[0usize]));
        counters.push(registry.register_counter(&INFO[1usize]));
        counters.push(registry.register_counter(&INFO[2usize]));
        counters.push(registry.register_counter(&INFO[3usize]));
        counters.push(registry.register_counter(&INFO[5usize]));
        counters.push(registry.register_counter(&INFO[7usize]));
        counters.push(registry.register_counter(&INFO[9usize]));
        counters.push(registry.register_counter(&INFO[10usize]));
        counters.push(registry.register_counter(&INFO[11usize]));
        counters.push(registry.register_counter(&INFO[14usize]));
        counters.push(registry.register_counter(&INFO[17usize]));
        counters.push(registry.register_counter(&INFO[19usize]));
        counters.push(registry.register_counter(&INFO[21usize]));
        counters.push(registry.register_counter(&INFO[24usize]));
        counters.push(registry.register_counter(&INFO[34usize]));
        counters.push(registry.register_counter(&INFO[36usize]));
        counters.push(registry.register_counter(&INFO[37usize]));
        counters.push(registry.register_counter(&INFO[39usize]));
        counters.push(registry.register_counter(&INFO[41usize]));
        counters.push(registry.register_counter(&INFO[43usize]));
        counters.push(registry.register_counter(&INFO[46usize]));
        counters.push(registry.register_counter(&INFO[51usize]));
        counters.push(registry.register_counter(&INFO[52usize]));
        counters.push(registry.register_counter(&INFO[55usize]));
        counters.push(registry.register_counter(&INFO[57usize]));
        counters.push(registry.register_counter(&INFO[58usize]));
        counters.push(registry.register_counter(&INFO[61usize]));
        counters.push(registry.register_counter(&INFO[62usize]));
        counters.push(registry.register_counter(&INFO[64usize]));
        counters.push(registry.register_counter(&INFO[65usize]));
        counters.push(registry.register_counter(&INFO[68usize]));
        counters.push(registry.register_counter(&INFO[69usize]));
        counters.push(registry.register_counter(&INFO[71usize]));
        counters.push(registry.register_counter(&INFO[73usize]));
        counters.push(registry.register_counter(&INFO[78usize]));
        counters.push(registry.register_counter(&INFO[79usize]));
        counters.push(registry.register_counter(&INFO[81usize]));
        counters.push(registry.register_counter(&INFO[83usize]));
        counters.push(registry.register_counter(&INFO[85usize]));
        counters.push(registry.register_counter(&INFO[86usize]));
        counters.push(registry.register_counter(&INFO[88usize]));
        counters.push(registry.register_counter(&INFO[89usize]));
        counters.push(registry.register_counter(&INFO[91usize]));
        counters.push(registry.register_counter(&INFO[92usize]));
        counters.push(registry.register_counter(&INFO[96usize]));
        counters.push(registry.register_counter(&INFO[100usize]));
        counters.push(registry.register_counter(&INFO[101usize]));
        counters.push(registry.register_counter(&INFO[105usize]));
        counters.push(registry.register_counter(&INFO[107usize]));
        counters.push(registry.register_counter(&INFO[113usize]));
        counters.push(registry.register_counter(&INFO[116usize]));
        counters.push(registry.register_counter(&INFO[117usize]));
        counters.push(registry.register_counter(&INFO[118usize]));
        counters.push(registry.register_counter(&INFO[119usize]));
        counters.push(registry.register_counter(&INFO[123usize]));
        counters.push(registry.register_counter(&INFO[126usize]));
        counters.push(registry.register_counter(&INFO[130usize]));
        counters.push(registry.register_counter(&INFO[132usize]));
        counters.push(registry.register_counter(&INFO[133usize]));
        counters.push(registry.register_counter(&INFO[135usize]));
        counters.push(registry.register_counter(&INFO[137usize]));
        counters.push(registry.register_counter(&INFO[139usize]));
        counters.push(registry.register_counter(&INFO[141usize]));
        counters.push(registry.register_counter(&INFO[143usize]));
        counters.push(registry.register_counter(&INFO[144usize]));
        counters.push(registry.register_counter(&INFO[145usize]));
        counters.push(registry.register_counter(&INFO[147usize]));
        counters.push(registry.register_counter(&INFO[149usize]));
        counters.push(registry.register_counter(&INFO[151usize]));
        counters.push(registry.register_counter(&INFO[153usize]));
        counters.push(registry.register_counter(&INFO[155usize]));
        counters.push(registry.register_counter(&INFO[156usize]));
        counters.push(registry.register_counter(&INFO[157usize]));
        counters.push(registry.register_counter(&INFO[158usize]));
        counters.push(registry.register_counter(&INFO[160usize]));
        bool_counters.push(registry.register_bool_counter(&INFO[23usize]));
        bool_counters.push(registry.register_bool_counter(&INFO[33usize]));
        bool_counters.push(registry.register_bool_counter(&INFO[95usize]));
        {
            #[allow(unused_imports)]
            use api::*;
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <PacketHeader as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[4usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <PacketHeader as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[8usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <PacketHeader as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[12usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <Frame as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[13usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <PacketHeader as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[15usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <Frame as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[16usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <PacketHeader as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[18usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <PacketHeader as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[20usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <CongestionSource as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[35usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <PacketHeader as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[38usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <PacketHeader as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[40usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <PacketDropReason as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[42usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <KeyType as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[44usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <CipherSuite as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[45usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <KeySpace as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[50usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <PacketHeader as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[53usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <DuplicatePacketError as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[54usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <DatagramDropReason as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[67usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <EcnState as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[70usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <MigrationDenyReason as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[72usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <HandshakeStatus as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[77usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <PathChallengeStatus as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[80usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <MtuUpdatedCause as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[94usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <SlowStartExitCause as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[97usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <BbrState as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[106usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <DcState as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[112usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <crate::connection::Error as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[115usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <DatagramDropReason as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[129usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
            {
                let offset = nominal_counters.len();
                let mut count = 0;
                for variant in <crate::connection::Error as AsVariant>::VARIANTS.iter() {
                    nominal_counters
                        .push(registry.register_nominal_counter(&INFO[131usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_counter_offsets.push(offset);
            }
        }
        measures.push(registry.register_measure(&INFO[6usize]));
        measures.push(registry.register_measure(&INFO[22usize]));
        measures.push(registry.register_measure(&INFO[25usize]));
        measures.push(registry.register_measure(&INFO[26usize]));
        measures.push(registry.register_measure(&INFO[27usize]));
        measures.push(registry.register_measure(&INFO[28usize]));
        measures.push(registry.register_measure(&INFO[29usize]));
        measures.push(registry.register_measure(&INFO[30usize]));
        measures.push(registry.register_measure(&INFO[31usize]));
        measures.push(registry.register_measure(&INFO[32usize]));
        measures.push(registry.register_measure(&INFO[59usize]));
        measures.push(registry.register_measure(&INFO[60usize]));
        measures.push(registry.register_measure(&INFO[63usize]));
        measures.push(registry.register_measure(&INFO[66usize]));
        measures.push(registry.register_measure(&INFO[87usize]));
        measures.push(registry.register_measure(&INFO[90usize]));
        measures.push(registry.register_measure(&INFO[93usize]));
        measures.push(registry.register_measure(&INFO[99usize]));
        measures.push(registry.register_measure(&INFO[102usize]));
        measures.push(registry.register_measure(&INFO[103usize]));
        measures.push(registry.register_measure(&INFO[104usize]));
        measures.push(registry.register_measure(&INFO[120usize]));
        measures.push(registry.register_measure(&INFO[121usize]));
        measures.push(registry.register_measure(&INFO[122usize]));
        measures.push(registry.register_measure(&INFO[124usize]));
        measures.push(registry.register_measure(&INFO[125usize]));
        measures.push(registry.register_measure(&INFO[127usize]));
        measures.push(registry.register_measure(&INFO[128usize]));
        measures.push(registry.register_measure(&INFO[134usize]));
        measures.push(registry.register_measure(&INFO[136usize]));
        measures.push(registry.register_measure(&INFO[138usize]));
        measures.push(registry.register_measure(&INFO[140usize]));
        measures.push(registry.register_measure(&INFO[142usize]));
        measures.push(registry.register_measure(&INFO[146usize]));
        measures.push(registry.register_measure(&INFO[148usize]));
        measures.push(registry.register_measure(&INFO[150usize]));
        measures.push(registry.register_measure(&INFO[152usize]));
        measures.push(registry.register_measure(&INFO[154usize]));
        timers.push(registry.register_timer(&INFO[47usize]));
        timers.push(registry.register_timer(&INFO[48usize]));
        timers.push(registry.register_timer(&INFO[49usize]));
        timers.push(registry.register_timer(&INFO[56usize]));
        timers.push(registry.register_timer(&INFO[74usize]));
        timers.push(registry.register_timer(&INFO[75usize]));
        timers.push(registry.register_timer(&INFO[76usize]));
        timers.push(registry.register_timer(&INFO[82usize]));
        timers.push(registry.register_timer(&INFO[84usize]));
        timers.push(registry.register_timer(&INFO[108usize]));
        timers.push(registry.register_timer(&INFO[109usize]));
        timers.push(registry.register_timer(&INFO[110usize]));
        timers.push(registry.register_timer(&INFO[111usize]));
        timers.push(registry.register_timer(&INFO[114usize]));
        timers.push(registry.register_timer(&INFO[159usize]));
        {
            #[allow(unused_imports)]
            use api::*;
            {
                let offset = nominal_timers.len();
                let mut count = 0;
                for variant in <SlowStartExitCause as AsVariant>::VARIANTS.iter() {
                    nominal_timers.push(registry.register_nominal_timer(&INFO[98usize], variant));
                    count += 1;
                }
                debug_assert_ne!(count, 0, "field type needs at least one variant");
                nominal_timer_offsets.push(offset);
            }
        }
        Self {
            counters: counters
                .try_into()
                .unwrap_or_else(|_| panic!("invalid len")),
            bool_counters: bool_counters
                .try_into()
                .unwrap_or_else(|_| panic!("invalid len")),
            nominal_counters: nominal_counters.into(),
            nominal_counter_offsets: nominal_counter_offsets
                .try_into()
                .unwrap_or_else(|_| panic!("invalid len")),
            measures: measures
                .try_into()
                .unwrap_or_else(|_| panic!("invalid len")),
            gauges: gauges.try_into().unwrap_or_else(|_| panic!("invalid len")),
            timers: timers.try_into().unwrap_or_else(|_| panic!("invalid len")),
            nominal_timers: nominal_timers.into(),
            nominal_timer_offsets: nominal_timer_offsets
                .try_into()
                .unwrap_or_else(|_| panic!("invalid len")),
            registry,
        }
    }
    #[doc = r" Returns all of the registered counters"]
    #[inline]
    pub fn counters(&self) -> impl Iterator<Item = (&'static Info, &R::Counter)> + '_ {
        self.counters
            .iter()
            .enumerate()
            .map(|(idx, entry)| match idx {
                0usize => (&INFO[0usize], entry),
                1usize => (&INFO[1usize], entry),
                2usize => (&INFO[2usize], entry),
                3usize => (&INFO[3usize], entry),
                4usize => (&INFO[5usize], entry),
                5usize => (&INFO[7usize], entry),
                6usize => (&INFO[9usize], entry),
                7usize => (&INFO[10usize], entry),
                8usize => (&INFO[11usize], entry),
                9usize => (&INFO[14usize], entry),
                10usize => (&INFO[17usize], entry),
                11usize => (&INFO[19usize], entry),
                12usize => (&INFO[21usize], entry),
                13usize => (&INFO[24usize], entry),
                14usize => (&INFO[34usize], entry),
                15usize => (&INFO[36usize], entry),
                16usize => (&INFO[37usize], entry),
                17usize => (&INFO[39usize], entry),
                18usize => (&INFO[41usize], entry),
                19usize => (&INFO[43usize], entry),
                20usize => (&INFO[46usize], entry),
                21usize => (&INFO[51usize], entry),
                22usize => (&INFO[52usize], entry),
                23usize => (&INFO[55usize], entry),
                24usize => (&INFO[57usize], entry),
                25usize => (&INFO[58usize], entry),
                26usize => (&INFO[61usize], entry),
                27usize => (&INFO[62usize], entry),
                28usize => (&INFO[64usize], entry),
                29usize => (&INFO[65usize], entry),
                30usize => (&INFO[68usize], entry),
                31usize => (&INFO[69usize], entry),
                32usize => (&INFO[71usize], entry),
                33usize => (&INFO[73usize], entry),
                34usize => (&INFO[78usize], entry),
                35usize => (&INFO[79usize], entry),
                36usize => (&INFO[81usize], entry),
                37usize => (&INFO[83usize], entry),
                38usize => (&INFO[85usize], entry),
                39usize => (&INFO[86usize], entry),
                40usize => (&INFO[88usize], entry),
                41usize => (&INFO[89usize], entry),
                42usize => (&INFO[91usize], entry),
                43usize => (&INFO[92usize], entry),
                44usize => (&INFO[96usize], entry),
                45usize => (&INFO[100usize], entry),
                46usize => (&INFO[101usize], entry),
                47usize => (&INFO[105usize], entry),
                48usize => (&INFO[107usize], entry),
                49usize => (&INFO[113usize], entry),
                50usize => (&INFO[116usize], entry),
                51usize => (&INFO[117usize], entry),
                52usize => (&INFO[118usize], entry),
                53usize => (&INFO[119usize], entry),
                54usize => (&INFO[123usize], entry),
                55usize => (&INFO[126usize], entry),
                56usize => (&INFO[130usize], entry),
                57usize => (&INFO[132usize], entry),
                58usize => (&INFO[133usize], entry),
                59usize => (&INFO[135usize], entry),
                60usize => (&INFO[137usize], entry),
                61usize => (&INFO[139usize], entry),
                62usize => (&INFO[141usize], entry),
                63usize => (&INFO[143usize], entry),
                64usize => (&INFO[144usize], entry),
                65usize => (&INFO[145usize], entry),
                66usize => (&INFO[147usize], entry),
                67usize => (&INFO[149usize], entry),
                68usize => (&INFO[151usize], entry),
                69usize => (&INFO[153usize], entry),
                70usize => (&INFO[155usize], entry),
                71usize => (&INFO[156usize], entry),
                72usize => (&INFO[157usize], entry),
                73usize => (&INFO[158usize], entry),
                74usize => (&INFO[160usize], entry),
                _ => unsafe { core::hint::unreachable_unchecked() },
            })
    }
    #[allow(dead_code)]
    #[inline(always)]
    fn count<T: Metric>(&self, info: usize, id: usize, value: T) {
        let info = &INFO[info];
        let counter = &self.counters[id];
        counter.record(info, value);
    }
    #[doc = r" Returns all of the registered bool counters"]
    #[inline]
    pub fn bool_counters(&self) -> impl Iterator<Item = (&'static Info, &R::BoolCounter)> + '_ {
        self.bool_counters
            .iter()
            .enumerate()
            .map(|(idx, entry)| match idx {
                0usize => (&INFO[23usize], entry),
                1usize => (&INFO[33usize], entry),
                2usize => (&INFO[95usize], entry),
                _ => unsafe { core::hint::unreachable_unchecked() },
            })
    }
    #[allow(dead_code)]
    #[inline(always)]
    fn count_bool(&self, info: usize, id: usize, value: bool) {
        let info = &INFO[info];
        let counter = &self.bool_counters[id];
        counter.record(info, value);
    }
    #[doc = r" Returns all of the registered nominal counters"]
    #[inline]
    pub fn nominal_counters(
        &self,
    ) -> impl Iterator<Item = (&'static Info, &[R::NominalCounter], &[info::Variant])> + '_ {
        use api::*;
        self.nominal_counter_offsets
            .iter()
            .enumerate()
            .map(|(idx, entry)| match idx {
                0usize => {
                    let offset = *entry;
                    let variants = <PacketHeader as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[4usize], entries, variants)
                }
                1usize => {
                    let offset = *entry;
                    let variants = <PacketHeader as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[8usize], entries, variants)
                }
                2usize => {
                    let offset = *entry;
                    let variants = <PacketHeader as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[12usize], entries, variants)
                }
                3usize => {
                    let offset = *entry;
                    let variants = <Frame as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[13usize], entries, variants)
                }
                4usize => {
                    let offset = *entry;
                    let variants = <PacketHeader as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[15usize], entries, variants)
                }
                5usize => {
                    let offset = *entry;
                    let variants = <Frame as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[16usize], entries, variants)
                }
                6usize => {
                    let offset = *entry;
                    let variants = <PacketHeader as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[18usize], entries, variants)
                }
                7usize => {
                    let offset = *entry;
                    let variants = <PacketHeader as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[20usize], entries, variants)
                }
                8usize => {
                    let offset = *entry;
                    let variants = <CongestionSource as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[35usize], entries, variants)
                }
                9usize => {
                    let offset = *entry;
                    let variants = <PacketHeader as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[38usize], entries, variants)
                }
                10usize => {
                    let offset = *entry;
                    let variants = <PacketHeader as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[40usize], entries, variants)
                }
                11usize => {
                    let offset = *entry;
                    let variants = <PacketDropReason as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[42usize], entries, variants)
                }
                12usize => {
                    let offset = *entry;
                    let variants = <KeyType as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[44usize], entries, variants)
                }
                13usize => {
                    let offset = *entry;
                    let variants = <CipherSuite as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[45usize], entries, variants)
                }
                14usize => {
                    let offset = *entry;
                    let variants = <KeySpace as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[50usize], entries, variants)
                }
                15usize => {
                    let offset = *entry;
                    let variants = <PacketHeader as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[53usize], entries, variants)
                }
                16usize => {
                    let offset = *entry;
                    let variants = <DuplicatePacketError as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[54usize], entries, variants)
                }
                17usize => {
                    let offset = *entry;
                    let variants = <DatagramDropReason as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[67usize], entries, variants)
                }
                18usize => {
                    let offset = *entry;
                    let variants = <EcnState as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[70usize], entries, variants)
                }
                19usize => {
                    let offset = *entry;
                    let variants = <MigrationDenyReason as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[72usize], entries, variants)
                }
                20usize => {
                    let offset = *entry;
                    let variants = <HandshakeStatus as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[77usize], entries, variants)
                }
                21usize => {
                    let offset = *entry;
                    let variants = <PathChallengeStatus as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[80usize], entries, variants)
                }
                22usize => {
                    let offset = *entry;
                    let variants = <MtuUpdatedCause as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[94usize], entries, variants)
                }
                23usize => {
                    let offset = *entry;
                    let variants = <SlowStartExitCause as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[97usize], entries, variants)
                }
                24usize => {
                    let offset = *entry;
                    let variants = <BbrState as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[106usize], entries, variants)
                }
                25usize => {
                    let offset = *entry;
                    let variants = <DcState as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[112usize], entries, variants)
                }
                26usize => {
                    let offset = *entry;
                    let variants = <crate::connection::Error as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[115usize], entries, variants)
                }
                27usize => {
                    let offset = *entry;
                    let variants = <DatagramDropReason as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[129usize], entries, variants)
                }
                28usize => {
                    let offset = *entry;
                    let variants = <crate::connection::Error as AsVariant>::VARIANTS;
                    let entries = &self.nominal_counters[offset..offset + variants.len()];
                    (&INFO[131usize], entries, variants)
                }
                _ => unsafe { core::hint::unreachable_unchecked() },
            })
    }
    #[allow(dead_code)]
    #[inline(always)]
    fn count_nominal<T: AsVariant>(&self, info: usize, id: usize, value: &T) {
        let info = &INFO[info];
        let idx = self.nominal_counter_offsets[id] + value.variant_idx();
        let counter = &self.nominal_counters[idx];
        counter.record(info, value.as_variant(), 1usize);
    }
    #[doc = r" Returns all of the registered measures"]
    #[inline]
    pub fn measures(&self) -> impl Iterator<Item = (&'static Info, &R::Measure)> + '_ {
        self.measures
            .iter()
            .enumerate()
            .map(|(idx, entry)| match idx {
                0usize => (&INFO[6usize], entry),
                1usize => (&INFO[22usize], entry),
                2usize => (&INFO[25usize], entry),
                3usize => (&INFO[26usize], entry),
                4usize => (&INFO[27usize], entry),
                5usize => (&INFO[28usize], entry),
                6usize => (&INFO[29usize], entry),
                7usize => (&INFO[30usize], entry),
                8usize => (&INFO[31usize], entry),
                9usize => (&INFO[32usize], entry),
                10usize => (&INFO[59usize], entry),
                11usize => (&INFO[60usize], entry),
                12usize => (&INFO[63usize], entry),
                13usize => (&INFO[66usize], entry),
                14usize => (&INFO[87usize], entry),
                15usize => (&INFO[90usize], entry),
                16usize => (&INFO[93usize], entry),
                17usize => (&INFO[99usize], entry),
                18usize => (&INFO[102usize], entry),
                19usize => (&INFO[103usize], entry),
                20usize => (&INFO[104usize], entry),
                21usize => (&INFO[120usize], entry),
                22usize => (&INFO[121usize], entry),
                23usize => (&INFO[122usize], entry),
                24usize => (&INFO[124usize], entry),
                25usize => (&INFO[125usize], entry),
                26usize => (&INFO[127usize], entry),
                27usize => (&INFO[128usize], entry),
                28usize => (&INFO[134usize], entry),
                29usize => (&INFO[136usize], entry),
                30usize => (&INFO[138usize], entry),
                31usize => (&INFO[140usize], entry),
                32usize => (&INFO[142usize], entry),
                33usize => (&INFO[146usize], entry),
                34usize => (&INFO[148usize], entry),
                35usize => (&INFO[150usize], entry),
                36usize => (&INFO[152usize], entry),
                37usize => (&INFO[154usize], entry),
                _ => unsafe { core::hint::unreachable_unchecked() },
            })
    }
    #[allow(dead_code)]
    #[inline(always)]
    fn measure<T: Metric>(&self, info: usize, id: usize, value: T) {
        let info = &INFO[info];
        let measure = &self.measures[id];
        measure.record(info, value);
    }
    #[doc = r" Returns all of the registered gauges"]
    #[inline]
    pub fn gauges(&self) -> impl Iterator<Item = (&'static Info, &R::Gauge)> + '_ {
        core::iter::empty()
    }
    #[allow(dead_code)]
    #[inline(always)]
    fn gauge<T: Metric>(&self, info: usize, id: usize, value: T) {
        let info = &INFO[info];
        let gauge = &self.gauges[id];
        gauge.record(info, value);
    }
    #[doc = r" Returns all of the registered timers"]
    #[inline]
    pub fn timers(&self) -> impl Iterator<Item = (&'static Info, &R::Timer)> + '_ {
        self.timers
            .iter()
            .enumerate()
            .map(|(idx, entry)| match idx {
                0usize => (&INFO[47usize], entry),
                1usize => (&INFO[48usize], entry),
                2usize => (&INFO[49usize], entry),
                3usize => (&INFO[56usize], entry),
                4usize => (&INFO[74usize], entry),
                5usize => (&INFO[75usize], entry),
                6usize => (&INFO[76usize], entry),
                7usize => (&INFO[82usize], entry),
                8usize => (&INFO[84usize], entry),
                9usize => (&INFO[108usize], entry),
                10usize => (&INFO[109usize], entry),
                11usize => (&INFO[110usize], entry),
                12usize => (&INFO[111usize], entry),
                13usize => (&INFO[114usize], entry),
                14usize => (&INFO[159usize], entry),
                _ => unsafe { core::hint::unreachable_unchecked() },
            })
    }
    #[allow(dead_code)]
    #[inline(always)]
    fn time(&self, info: usize, id: usize, value: core::time::Duration) {
        let info = &INFO[info];
        let timer = &self.timers[id];
        timer.record(info, value);
    }
    #[allow(dead_code)]
    #[inline(always)]
    fn time_nominal<T: AsVariant>(
        &self,
        info: usize,
        id: usize,
        value: &T,
        duration: core::time::Duration,
    ) {
        let info = &INFO[info];
        let idx = self.nominal_timer_offsets[id] + value.variant_idx();
        let counter = &self.nominal_timers[idx];
        counter.record(info, value.as_variant(), duration);
    }
}
impl<R: Registry> event::Subscriber for Subscriber<R> {
    type ConnectionContext = ConnectionContext;
    fn create_connection_context(
        &mut self,
        meta: &api::ConnectionMeta,
        _info: &api::ConnectionInfo,
    ) -> Self::ConnectionContext {
        Self::ConnectionContext {
            start_time: meta.timestamp,
        }
    }
    #[inline]
    fn on_application_protocol_information(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::ApplicationProtocolInformation,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(0usize, 0usize, 1usize);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_server_name_information(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::ServerNameInformation,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(1usize, 1usize, 1usize);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_packet_skipped(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::PacketSkipped,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(2usize, 2usize, 1usize);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_packet_sent(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::PacketSent,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(3usize, 3usize, 1usize);
        self.count_nominal(4usize, 0usize, &event.packet_header);
        self.count(5usize, 4usize, event.packet_len);
        self.measure(6usize, 0usize, event.packet_len);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_packet_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::PacketReceived,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(7usize, 5usize, 1usize);
        self.count_nominal(8usize, 1usize, &event.packet_header);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_active_path_updated(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::ActivePathUpdated,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(9usize, 6usize, 1usize);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_path_created(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::PathCreated,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(10usize, 7usize, 1usize);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_frame_sent(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::FrameSent,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(11usize, 8usize, 1usize);
        self.count_nominal(12usize, 2usize, &event.packet_header);
        self.count_nominal(13usize, 3usize, &event.frame);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_frame_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::FrameReceived,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(14usize, 9usize, 1usize);
        self.count_nominal(15usize, 4usize, &event.packet_header);
        self.count_nominal(16usize, 5usize, &event.frame);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_connection_close_frame_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::ConnectionCloseFrameReceived,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(17usize, 10usize, 1usize);
        self.count_nominal(18usize, 6usize, &event.packet_header);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_packet_lost(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::PacketLost,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(19usize, 11usize, 1usize);
        self.count_nominal(20usize, 7usize, &event.packet_header);
        self.count(21usize, 12usize, event.bytes_lost);
        self.measure(22usize, 1usize, event.bytes_lost);
        self.count_bool(23usize, 0usize, event.is_mtu_probe);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_recovery_metrics(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::RecoveryMetrics,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(24usize, 13usize, 1usize);
        self.measure(25usize, 2usize, event.min_rtt);
        self.measure(26usize, 3usize, event.smoothed_rtt);
        self.measure(27usize, 4usize, event.latest_rtt);
        self.measure(28usize, 5usize, event.rtt_variance);
        self.measure(29usize, 6usize, event.max_ack_delay);
        self.measure(30usize, 7usize, event.pto_count);
        self.measure(31usize, 8usize, event.congestion_window);
        self.measure(32usize, 9usize, event.bytes_in_flight);
        self.count_bool(33usize, 1usize, event.congestion_limited);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_congestion(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::Congestion,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(34usize, 14usize, 1usize);
        self.count_nominal(35usize, 8usize, &event.source);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_rx_ack_range_dropped(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::RxAckRangeDropped,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(36usize, 15usize, 1usize);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_ack_range_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::AckRangeReceived,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(37usize, 16usize, 1usize);
        self.count_nominal(38usize, 9usize, &event.packet_header);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_ack_range_sent(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::AckRangeSent,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(39usize, 17usize, 1usize);
        self.count_nominal(40usize, 10usize, &event.packet_header);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_packet_dropped(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::PacketDropped,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(41usize, 18usize, 1usize);
        self.count_nominal(42usize, 11usize, &event.reason);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_key_update(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::KeyUpdate,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(43usize, 19usize, 1usize);
        self.count_nominal(44usize, 12usize, &event.key_type);
        self.count_nominal(45usize, 13usize, &event.cipher_suite);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_key_space_discarded(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::KeySpaceDiscarded,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(46usize, 20usize, 1usize);
        {
            fn check(evt: &api::KeySpaceDiscarded) -> bool {
                matches!(evt.space, KeySpace::Initial { .. })
            }
            if check(event) {
                self.time(
                    47usize,
                    0usize,
                    meta.timestamp.saturating_duration_since(context.start_time),
                );
            }
        }
        {
            fn check(evt: &api::KeySpaceDiscarded) -> bool {
                matches!(evt.space, KeySpace::Handshake { .. })
            }
            if check(event) {
                self.time(
                    48usize,
                    1usize,
                    meta.timestamp.saturating_duration_since(context.start_time),
                );
            }
        }
        {
            fn check(evt: &api::KeySpaceDiscarded) -> bool {
                matches!(evt.space, KeySpace::OneRtt { .. })
            }
            if check(event) {
                self.time(
                    49usize,
                    2usize,
                    meta.timestamp.saturating_duration_since(context.start_time),
                );
            }
        }
        self.count_nominal(50usize, 14usize, &event.space);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_connection_started(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::ConnectionStarted,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(51usize, 21usize, 1usize);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_duplicate_packet(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::DuplicatePacket,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(52usize, 22usize, 1usize);
        self.count_nominal(53usize, 15usize, &event.packet_header);
        self.count_nominal(54usize, 16usize, &event.error);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_transport_parameters_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::TransportParametersReceived,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(55usize, 23usize, 1usize);
        self.time(
            56usize,
            3usize,
            meta.timestamp.saturating_duration_since(context.start_time),
        );
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_datagram_sent(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::DatagramSent,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(57usize, 24usize, 1usize);
        self.count(58usize, 25usize, event.len);
        self.measure(59usize, 10usize, event.len);
        self.measure(60usize, 11usize, event.gso_offset);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_datagram_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::DatagramReceived,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(61usize, 26usize, 1usize);
        self.count(62usize, 27usize, event.len);
        self.measure(63usize, 12usize, event.len);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_datagram_dropped(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::DatagramDropped,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(64usize, 28usize, 1usize);
        self.count(65usize, 29usize, event.len);
        self.measure(66usize, 13usize, event.len);
        self.count_nominal(67usize, 17usize, &event.reason);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_connection_id_updated(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::ConnectionIdUpdated,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(68usize, 30usize, 1usize);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_ecn_state_changed(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::EcnStateChanged,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(69usize, 31usize, 1usize);
        self.count_nominal(70usize, 18usize, &event.state);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_connection_migration_denied(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::ConnectionMigrationDenied,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(71usize, 32usize, 1usize);
        self.count_nominal(72usize, 19usize, &event.reason);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_handshake_status_updated(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::HandshakeStatusUpdated,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(73usize, 33usize, 1usize);
        {
            fn check(evt: &api::HandshakeStatusUpdated) -> bool {
                matches!(evt.status, HandshakeStatus::Complete { .. })
            }
            if check(event) {
                self.time(
                    74usize,
                    4usize,
                    meta.timestamp.saturating_duration_since(context.start_time),
                );
            }
        }
        {
            fn check(evt: &api::HandshakeStatusUpdated) -> bool {
                matches!(evt.status, HandshakeStatus::Confirmed { .. })
            }
            if check(event) {
                self.time(
                    75usize,
                    5usize,
                    meta.timestamp.saturating_duration_since(context.start_time),
                );
            }
        }
        {
            fn check(evt: &api::HandshakeStatusUpdated) -> bool {
                matches!(evt.status, HandshakeStatus::HandshakeDoneAcked { .. })
            }
            if check(event) {
                self.time(
                    76usize,
                    6usize,
                    meta.timestamp.saturating_duration_since(context.start_time),
                );
            }
        }
        self.count_nominal(77usize, 20usize, &event.status);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_tls_exporter_ready(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::TlsExporterReady,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(78usize, 34usize, 1usize);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_path_challenge_updated(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::PathChallengeUpdated,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(79usize, 35usize, 1usize);
        self.count_nominal(80usize, 21usize, &event.path_challenge_status);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_tls_client_hello(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::TlsClientHello,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(81usize, 36usize, 1usize);
        self.time(
            82usize,
            7usize,
            meta.timestamp.saturating_duration_since(context.start_time),
        );
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_tls_server_hello(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::TlsServerHello,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(83usize, 37usize, 1usize);
        self.time(
            84usize,
            8usize,
            meta.timestamp.saturating_duration_since(context.start_time),
        );
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_rx_stream_progress(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::RxStreamProgress,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(85usize, 38usize, 1usize);
        self.count(86usize, 39usize, event.bytes);
        self.measure(87usize, 14usize, event.bytes);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_tx_stream_progress(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::TxStreamProgress,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(88usize, 40usize, 1usize);
        self.count(89usize, 41usize, event.bytes);
        self.measure(90usize, 15usize, event.bytes);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_keep_alive_timer_expired(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::KeepAliveTimerExpired,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(91usize, 42usize, 1usize);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_mtu_updated(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::MtuUpdated,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(92usize, 43usize, 1usize);
        self.measure(93usize, 16usize, event.mtu);
        self.count_nominal(94usize, 22usize, &event.cause);
        self.count_bool(95usize, 2usize, event.search_complete);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_slow_start_exited(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::SlowStartExited,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(96usize, 44usize, 1usize);
        self.count_nominal(97usize, 23usize, &event.cause);
        self.time_nominal(
            98usize,
            0usize,
            &event.cause,
            meta.timestamp.saturating_duration_since(context.start_time),
        );
        self.measure(99usize, 17usize, event.congestion_window);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_delivery_rate_sampled(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::DeliveryRateSampled,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(100usize, 45usize, 1usize);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_pacing_rate_updated(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::PacingRateUpdated,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(101usize, 46usize, 1usize);
        self.measure(102usize, 18usize, event.bytes_per_second);
        self.measure(103usize, 19usize, event.burst_size);
        self.measure(104usize, 20usize, event.pacing_gain);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_bbr_state_changed(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::BbrStateChanged,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(105usize, 47usize, 1usize);
        self.count_nominal(106usize, 24usize, &event.state);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_dc_state_changed(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::DcStateChanged,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(107usize, 48usize, 1usize);
        {
            fn check(evt: &api::DcStateChanged) -> bool {
                matches!(evt.state, DcState::VersionNegotiated { .. })
            }
            if check(event) {
                self.time(
                    108usize,
                    9usize,
                    meta.timestamp.saturating_duration_since(context.start_time),
                );
            }
        }
        {
            fn check(evt: &api::DcStateChanged) -> bool {
                matches!(evt.state, DcState::VersionNegotiated { .. })
            }
            if check(event) {
                self.time(
                    109usize,
                    10usize,
                    meta.timestamp.saturating_duration_since(context.start_time),
                );
            }
        }
        {
            fn check(evt: &api::DcStateChanged) -> bool {
                matches!(evt.state, DcState::PathSecretsReady { .. })
            }
            if check(event) {
                self.time(
                    110usize,
                    11usize,
                    meta.timestamp.saturating_duration_since(context.start_time),
                );
            }
        }
        {
            fn check(evt: &api::DcStateChanged) -> bool {
                matches!(evt.state, DcState::Complete { .. })
            }
            if check(event) {
                self.time(
                    111usize,
                    12usize,
                    meta.timestamp.saturating_duration_since(context.start_time),
                );
            }
        }
        self.count_nominal(112usize, 25usize, &event.state);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_connection_closed(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &api::ConnectionMeta,
        event: &api::ConnectionClosed,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(113usize, 49usize, 1usize);
        self.time(
            114usize,
            13usize,
            meta.timestamp.saturating_duration_since(context.start_time),
        );
        self.count_nominal(115usize, 26usize, &event.error);
        let _ = context;
        let _ = meta;
        let _ = event;
    }
    #[inline]
    fn on_version_information(
        &mut self,
        meta: &api::EndpointMeta,
        event: &api::VersionInformation,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(116usize, 50usize, 1usize);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_endpoint_packet_sent(
        &mut self,
        meta: &api::EndpointMeta,
        event: &api::EndpointPacketSent,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(117usize, 51usize, 1usize);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_endpoint_packet_received(
        &mut self,
        meta: &api::EndpointMeta,
        event: &api::EndpointPacketReceived,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(118usize, 52usize, 1usize);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_endpoint_datagram_sent(
        &mut self,
        meta: &api::EndpointMeta,
        event: &api::EndpointDatagramSent,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(119usize, 53usize, 1usize);
        self.measure(120usize, 21usize, event.len);
        self.measure(121usize, 22usize, event.len);
        self.measure(122usize, 23usize, event.gso_offset);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_endpoint_datagram_received(
        &mut self,
        meta: &api::EndpointMeta,
        event: &api::EndpointDatagramReceived,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(123usize, 54usize, 1usize);
        self.measure(124usize, 24usize, event.len);
        self.measure(125usize, 25usize, event.len);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_endpoint_datagram_dropped(
        &mut self,
        meta: &api::EndpointMeta,
        event: &api::EndpointDatagramDropped,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(126usize, 55usize, 1usize);
        self.measure(127usize, 26usize, event.len);
        self.measure(128usize, 27usize, event.len);
        self.count_nominal(129usize, 27usize, &event.reason);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_endpoint_connection_attempt_failed(
        &mut self,
        meta: &api::EndpointMeta,
        event: &api::EndpointConnectionAttemptFailed,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(130usize, 56usize, 1usize);
        self.count_nominal(131usize, 28usize, &event.error);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_platform_tx(&mut self, meta: &api::EndpointMeta, event: &api::PlatformTx) {
        #[allow(unused_imports)]
        use api::*;
        self.count(132usize, 57usize, 1usize);
        self.count(133usize, 58usize, event.count);
        self.measure(134usize, 28usize, event.count);
        self.count(135usize, 59usize, event.syscalls);
        self.measure(136usize, 29usize, event.syscalls);
        self.count(137usize, 60usize, event.blocked_syscalls);
        self.measure(138usize, 30usize, event.blocked_syscalls);
        self.count(139usize, 61usize, event.total_errors);
        self.measure(140usize, 31usize, event.total_errors);
        self.count(141usize, 62usize, event.dropped_errors);
        self.measure(142usize, 32usize, event.dropped_errors);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_platform_tx_error(&mut self, meta: &api::EndpointMeta, event: &api::PlatformTxError) {
        #[allow(unused_imports)]
        use api::*;
        self.count(143usize, 63usize, 1usize);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_platform_rx(&mut self, meta: &api::EndpointMeta, event: &api::PlatformRx) {
        #[allow(unused_imports)]
        use api::*;
        self.count(144usize, 64usize, 1usize);
        self.count(145usize, 65usize, event.count);
        self.measure(146usize, 33usize, event.count);
        self.count(147usize, 66usize, event.syscalls);
        self.measure(148usize, 34usize, event.syscalls);
        self.count(149usize, 67usize, event.blocked_syscalls);
        self.measure(150usize, 35usize, event.blocked_syscalls);
        self.count(151usize, 68usize, event.total_errors);
        self.measure(152usize, 36usize, event.total_errors);
        self.count(153usize, 69usize, event.dropped_errors);
        self.measure(154usize, 37usize, event.dropped_errors);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_platform_rx_error(&mut self, meta: &api::EndpointMeta, event: &api::PlatformRxError) {
        #[allow(unused_imports)]
        use api::*;
        self.count(155usize, 70usize, 1usize);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_platform_feature_configured(
        &mut self,
        meta: &api::EndpointMeta,
        event: &api::PlatformFeatureConfigured,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(156usize, 71usize, 1usize);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_platform_event_loop_wakeup(
        &mut self,
        meta: &api::EndpointMeta,
        event: &api::PlatformEventLoopWakeup,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(157usize, 72usize, 1usize);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_platform_event_loop_sleep(
        &mut self,
        meta: &api::EndpointMeta,
        event: &api::PlatformEventLoopSleep,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(158usize, 73usize, 1usize);
        self.time(159usize, 14usize, event.processing_duration);
        let _ = event;
        let _ = meta;
    }
    #[inline]
    fn on_platform_event_loop_started(
        &mut self,
        meta: &api::EndpointMeta,
        event: &api::PlatformEventLoopStarted,
    ) {
        #[allow(unused_imports)]
        use api::*;
        self.count(160usize, 74usize, 1usize);
        let _ = event;
        let _ = meta;
    }
}
