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

enum bit<8> color_t { RED = 1, GREEN = 2, BLUE = 3 }
enum shape_t { CIRCLE, SQUARE, TRIANGLE }
type bit<20> id_t;

// Every packet is sent back to its ingress port. On the way, the data plane
// reads cell 0 of each register and writes a value computed from it to cell 1
// (and cell 2 for r_int), so that the tests can check that the data plane and
// P4Runtime agree on the values.
control ingress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    register<bit<16>>(8) r16;
    register<bit<160>>(4) r_wide;
    register<int<16>>(4) r_int;
    register<color_t>(4) r_color;
    register<shape_t>(4) r_shape;
    register<id_t>(4) r_id;
    apply {
        bit<16> v16;
        r16.read(v16, 0);
        r16.write(1, v16 + 1);
        bit<160> v_wide;
        r_wide.read(v_wide, 0);
        r_wide.write(1, v_wide + 1);
        // the shift is arithmetic, which shows that the value is signed
        int<16> v_int;
        r_int.read(v_int, 0);
        r_int.write(1, v_int - 1);
        r_int.write(2, v_int >> 1);
        color_t v_color;
        r_color.read(v_color, 0);
        if (v_color == color_t.GREEN) {
            r_color.write(1, color_t.BLUE);
        } else {
            r_color.write(1, color_t.RED);
        }
        shape_t v_shape;
        r_shape.read(v_shape, 0);
        if (v_shape == shape_t.SQUARE) {
            r_shape.write(1, shape_t.TRIANGLE);
        } else {
            r_shape.write(1, shape_t.CIRCLE);
        }
        id_t v_id;
        r_id.read(v_id, 0);
        r_id.write(1, (id_t)((bit<20>)v_id + 1));
        sm.egress_spec = sm.ingress_port;
    }
}

V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
