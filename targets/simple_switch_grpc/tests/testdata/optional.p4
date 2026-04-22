/*
 * Copyright 2020 VMware, Inc.
 * SPDX-FileCopyrightText: 2020 VMware, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <core.p4>
#include <v1model.p4>

header Hdr {
    bit<16> f1;
}

struct Headers {
    Hdr hdr;
}

struct Meta { }

parser p(packet_in b, out Headers h,
         inout Meta m, inout standard_metadata_t sm) {
    state start {
        b.extract(h.hdr);
        transition accept;
    }
}

control vrfy(inout Headers h, inout Meta m) { apply {} }
control update(inout Headers h, inout Meta m) { apply {} }

control ingress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    action send_1() { sm.egress_spec = 1; }
    action send_2() { sm.egress_spec = 2; }
    table opt {
        key = { h.hdr.f1 : optional; }
        actions = { NoAction; send_1; send_2; }
        default_action = NoAction();
    }
    apply { opt.apply(); }
}

control egress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    apply { }
}

control deparser(packet_out b, in Headers h) {
    apply { b.emit(h.hdr); }
}

V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
