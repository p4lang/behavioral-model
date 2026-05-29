/*
 * SPDX-FileCopyrightText: 2016 Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

parser start {
    return ingress;
}

action _nop() { }

table empty_key {
    actions { _nop; }
}

control ingress {
    apply(empty_key);
}
