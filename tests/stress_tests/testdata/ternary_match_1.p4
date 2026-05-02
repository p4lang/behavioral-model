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

table ternary_1 {
    reads {
        ethernet.dstAddr : ternary;
    }
    actions { _nop; }
    size : 65536;
}

table ternary_2 {
    reads {
        ethernet.srcAddr : ternary;
    }
    actions { _nop; }
    size : 65536;
}

table ternary_3 {
    reads {
        ethernet.srcAddr : ternary;
        ethernet.dstAddr : ternary;
    }
    actions { _nop; }
    size : 65536;
}

control ingress {
    apply(ternary_1);
    apply(ternary_2);
    apply(ternary_3);
}

control egress { }
