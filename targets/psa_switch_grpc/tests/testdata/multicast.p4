/*
 * SPDX-FileCopyrightText: 2018 Barefoot Networks, Inc.
 * Copyright 2018-present Barefoot Networks, Inc.
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
    apply { sm.mcast_grp = h.hdr.f1; }
}

control egress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    apply { h.hdr.f1 = sm.egress_rid; }
}

control deparser(packet_out b, in Headers h) {
    apply { b.emit(h.hdr); }
}

V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
