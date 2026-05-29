/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define CPU_PORT 64

parser start {
    return ingress;
}

action redirect() { modify_field(standard_metadata.egress_spec, CPU_PORT); }

table t_redirect {
    actions { redirect; }
    default_action: redirect();
}

control ingress {
    apply(t_redirect);
}

control egress { }
