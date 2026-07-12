/*
 * SPDX-FileCopyrightText: 2017 Google Inc.
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

control ingress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    @name(".cntr")
    direct_counter(CounterType.packets_and_bytes) cntr;
    @name(".port_redirect")
    action port_redirect() {
        sm.egress_spec = sm.ingress_port;
        cntr.count();
    }
    @name(".t_redirect")
    table t_redirect {
        key = { sm.packet_length : exact; }
        actions = { port_redirect; }
        counters = cntr;
    }
    apply { t_redirect.apply(); }
}

V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
