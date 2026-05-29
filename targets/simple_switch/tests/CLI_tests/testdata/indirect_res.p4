/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

parser start {
    return ingress;
}

header_type meta_t {
  fields {
    f : 32;
  }
}

header meta_t meta;

counter my_indirect_counter {
    type: packets;
    static: m_table;
    instance_count: 16;
}

meter my_indirect_meter {
    type: packets;
    static: m_table;
    instance_count: 16;
}

register my_register {
    width: 32;
    static: m_table;
    instance_count: 16;
}

action m_action() {
    count(my_indirect_counter, 1);
    execute_meter(my_indirect_meter, 1, meta.f);
    register_write(my_register, 1, 0xab);
}

table m_table {
    actions { m_action; }
    size : 1024;
}

control ingress {
    apply(m_table);
}

control egress {
}
