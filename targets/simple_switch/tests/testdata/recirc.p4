/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

header_type intrinsic_metadata_t {
    fields {
        mcast_grp : 4;
        egress_rid : 4;
        mcast_hash : 16;
        lf_field_list: 32;
        ingress_global_timestamp : 64;
        resubmit_flag : 16;
        recirculate_flag : 16;
    }
}

metadata intrinsic_metadata_t intrinsic_metadata;

header_type hdrA_t {
    fields {
        f1 : 8;
    }
}

header hdrA_t hdrA1;
header hdrA_t hdrA2;

parser start {
    extract(hdrA1);
    return select(hdrA1.f1) {
        0x00: ingress;
        default: more;
    }
}

parser more {
    extract(hdrA2);
    set_metadata(hdrA2.f1, 0xab);
    return ingress;
}

field_list recirc_FL {
    standard_metadata;
}

action loopback() {
    modify_field(standard_metadata.egress_spec, standard_metadata.ingress_port);
}

table t_loopback {
    actions { loopback; }
    default_action: loopback();
}

action recirc() {
    modify_field(hdrA1.f1, 0x01);
    add_header(hdrA2);
    recirculate(recirc_FL);
}

table t_recirc {
    actions { recirc; }
    default_action: recirc();
}

control ingress {
    apply(t_loopback);
}

control egress {
    if (hdrA1.f1 == 0) {
        apply(t_recirc);
    }
}
