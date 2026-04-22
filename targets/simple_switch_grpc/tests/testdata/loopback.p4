/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

parser start {
    return ingress;
}

action redirect() {
    modify_field(standard_metadata.egress_spec, standard_metadata.ingress_port);
}

table t_redirect {
    actions { redirect; }
    default_action: redirect();
}

control ingress {
    apply(t_redirect);
}

control egress { }
