/* Copyright 2013-present Barefoot Networks, Inc.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef PI_SRC_P4INFO_TABLES_INT_H_
#define PI_SRC_P4INFO_TABLES_INT_H_

#include "PI/p4info/tables.h"

#ifdef __cplusplus
extern "C" {
#endif

void pi_p4info_table_init(pi_p4info_t *p4info, size_t num_tables);

void pi_p4info_table_add(pi_p4info_t *p4info, pi_p4_id_t table_id,
                         const char *name, size_t num_match_fields,
                         size_t num_actions, size_t max_size, bool is_const,
                         bool supports_idle_timeout);

void pi_p4info_table_add_match_field(pi_p4info_t *p4info, pi_p4_id_t table_id,
                                     pi_p4_id_t field_id, const char *name,
                                     pi_p4info_match_type_t match_type,
                                     size_t bitwidth);

void pi_p4info_table_add_action(pi_p4info_t *p4info, pi_p4_id_t table_id,
                                pi_p4_id_t action_id,
                                pi_p4info_action_scope_t action_scope);

void pi_p4info_table_set_implementation(pi_p4info_t *p4info,
                                        pi_p4_id_t table_id,
                                        pi_p4_id_t implementation);

void pi_p4info_table_set_const_default_action(pi_p4info_t *p4info,
                                              pi_p4_id_t table_id,
                                              pi_p4_id_t default_action_id);

void pi_p4info_table_add_direct_resource(pi_p4info_t *p4info,
                                         pi_p4_id_t table_id,
                                         pi_p4_id_t direct_res_id);

#ifdef __cplusplus
}
#endif

#endif  // PI_SRC_P4INFO_TABLES_INT_H_
