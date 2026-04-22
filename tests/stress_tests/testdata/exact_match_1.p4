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

table exact_1 {
    reads {
        ethernet.dstAddr : exact;
    }
    actions { _nop; }
    size : 65536;
}

table exact_2 {
    reads {
        ethernet.srcAddr : exact;
    }
    actions { _nop; }
    size : 65536;
}

table exact_3 {
    reads {
        ethernet.srcAddr : exact;
        ethernet.dstAddr : exact;
    }
    actions { _nop; }
    size : 65536;
}

control ingress {
    apply(exact_1);
    apply(exact_2);
    apply(exact_3);
}

control egress { }
