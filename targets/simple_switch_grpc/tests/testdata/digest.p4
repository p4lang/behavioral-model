/*
 * SPDX-FileCopyrightText: 2018 Barefoot Networks, Inc.
 * Copyright 2018-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <core.p4>
#include <v1model.p4>

typedef bit<48> MacAddr_t;
typedef bit<9> PortId_t;

header Ethernet_t {
    MacAddr_t dmac;
    MacAddr_t smac;
    bit<16> ethertype;
}

struct Headers {
    Ethernet_t ethernet;
}

struct Meta { }

parser p(packet_in b, out Headers h,
         inout Meta m, inout standard_metadata_t sm) {
    state start {
        b.extract(h.ethernet);
        transition accept;
    }
}

control vrfy(inout Headers h, inout Meta m) { apply {} }
control update(inout Headers h, inout Meta m) { apply {} }

control egress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    apply {}
}

control deparser(packet_out b, in Headers h) {
    apply {
        b.emit(h.ethernet);
    }
}

struct L2_digest {
    MacAddr_t smac;
    PortId_t ig_port;
}

control ingress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    action send_digest() {
        digest<L2_digest>(1, {h.ethernet.smac, sm.ingress_port});
    }
    table smac {
        key = { h.ethernet.smac : exact; }
        actions = { send_digest; NoAction; }
        default_action = send_digest();
        size = 4096;
        support_timeout = true;
    }
    apply { smac.apply(); sm.egress_spec = sm.ingress_port; }
}

V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
