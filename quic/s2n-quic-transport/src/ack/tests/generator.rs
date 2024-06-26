// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bolero::generator::*;
use core::time::Duration;
use s2n_quic_core::ack;

pub fn gen_ack_settings() -> impl ValueGenerator<Output = ack::Settings> {
    (gen_duration(), 0..20).map_gen(|(max_ack_delay, ack_delay_exponent)| ack::Settings {
        max_ack_delay,
        ack_delay_exponent,
        ..Default::default()
    })
}

pub fn gen_duration() -> impl ValueGenerator<Output = Duration> {
    (1u16..10_000).map_gen(|millis| Duration::from_millis(millis as u64))
}
