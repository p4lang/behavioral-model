/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <core.p4>
#include <v1model.p4>

struct Headers {}

struct Meta {
    bit<3> color;
}

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

control ingress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    direct_meter<bit<3> >(MeterType.packets) mtr;
    action port_redirect() {
        sm.egress_spec = sm.ingress_port;
        mtr.read(m.color);
    }
    table t_redirect {
        key = { sm.ingress_port : exact; }
        actions = { port_redirect; }
        meters = mtr;
    }
    apply { t_redirect.apply(); }
}

V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
