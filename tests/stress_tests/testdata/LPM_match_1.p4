/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return ingress;
}

action _nop() { }

table LPM_1 {
    reads {
        ethernet.dstAddr : lpm;
    }
    actions { _nop; }
    size : 65536;
}

table LPM_2 {
    reads {
        ethernet.srcAddr : lpm;
    }
    actions { _nop; }
    size : 65536;
}

table LPM_3 {
    reads {
        ethernet.srcAddr : lpm;
        ethernet.dstAddr : exact;
    }
    actions { _nop; }
    size : 65536;
}

control ingress {
    apply(LPM_1);
    apply(LPM_2);
    apply(LPM_3);
}

control egress { }
