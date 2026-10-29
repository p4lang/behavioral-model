/*
 * SPDX-FileCopyrightText: 2026 Lorenzo Rinieri
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <core.p4>
#include <v1model.p4>

struct Headers {}

struct Meta {}

parser p(packet_in b, out Headers h,
         inout Meta m, inout standard_metadata_t sm) {
    state start {
        transition accept;
    }
}

control vrfy(inout Headers h, inout Meta m) { apply {} }
control update(inout Headers h, inout Meta m) { apply {} }

control egress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    apply {}
}

control deparser(packet_out b, in Headers h) {
    apply {}
}

// Every packet is sent back to its ingress port. On the way, for each register,
// the data plane reads cell 0, increments it and writes the result to cell 1.
control ingress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    register<bit<16>>(8) r16;
    register<bit<160>>(4) r_wide;
    apply {
        bit<16> v16;
        r16.read(v16, 0);
        r16.write(1, v16 + 1);
        bit<160> v_wide;
        r_wide.read(v_wide, 0);
        r_wide.write(1, v_wide + 1);
        sm.egress_spec = sm.ingress_port;
    }
}

V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
