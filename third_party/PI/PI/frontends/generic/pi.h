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

//! @file

#ifndef PI_INC_PI_FRONTENDS_GENERIC_PI_H_
#define PI_INC_PI_FRONTENDS_GENERIC_PI_H_

#include "PI/pi_base.h"
#include "PI/pi_tables.h"

typedef uint16_t pi_prefix_length_t;

////////// MATCH KEY //////////

//! Allocate a match jey object for a given table
pi_status_t pi_match_key_allocate(const pi_p4info_t *p4info,
                                  const pi_p4_id_t table_id,
                                  pi_match_key_t **key);

//! Reset state of a match key. This function does not perform any memory
//! allocation.
pi_status_t pi_match_key_init(pi_match_key_t *key);

void pi_match_key_set_priority(pi_match_key_t *key, pi_priority_t priority);

pi_priority_t pi_match_key_get_priority(pi_match_key_t *key);

pi_status_t pi_match_key_exact_set(pi_match_key_t *key, const pi_netv_t *fv);
pi_status_t pi_match_key_exact_get(const pi_match_key_t *key, pi_p4_id_t fid,
                                   pi_netv_t *fv);

pi_status_t pi_match_key_lpm_set(pi_match_key_t *key, const pi_netv_t *fv,
                                 const pi_prefix_length_t prefix_length);
pi_status_t pi_match_key_lpm_get(const pi_match_key_t *key, pi_p4_id_t fid,
                                 pi_netv_t *fv,
                                 pi_prefix_length_t *prefix_length);

pi_status_t pi_match_key_ternary_set(pi_match_key_t *key, const pi_netv_t *fv,
                                     const pi_netv_t *mask);
pi_status_t pi_match_key_ternary_get(const pi_match_key_t *key, pi_p4_id_t fid,
                                     pi_netv_t *fv, pi_netv_t *mask);

pi_status_t pi_match_key_optional_set(pi_match_key_t *key, const pi_netv_t *fv,
                                      bool is_wildcard);
pi_status_t pi_match_key_optional_get(const pi_match_key_t *key, pi_p4_id_t fid,
                                      pi_netv_t *fv, bool *is_wildcard);

pi_status_t pi_match_key_range_set(pi_match_key_t *key, const pi_netv_t *start,
                                   const pi_netv_t *end);
pi_status_t pi_match_key_range_get(const pi_match_key_t *key, pi_p4_id_t fid,
                                   pi_netv_t *start, pi_netv_t *end);

//! Destroy match key allocated with pi_match_key_allocate
pi_status_t pi_match_key_destroy(pi_match_key_t *key);

////////// ACTION DATA //////////

//! Allocate an action data object
pi_status_t pi_action_data_allocate(const pi_p4info_t *p4info,
                                    const pi_p4_id_t action_id,
                                    pi_action_data_t **adata);

//! Reset state of an action data. This function does not perform any memory
//! allocation.
pi_status_t pi_action_data_init(pi_action_data_t *adata);

pi_p4_id_t pi_action_data_action_id_get(const pi_action_data_t *adata);

pi_status_t pi_action_data_arg_set(pi_action_data_t *adata,
                                   const pi_netv_t *argv);
pi_status_t pi_action_data_arg_get(const pi_action_data_t *adata,
                                   pi_p4_id_t pid, pi_netv_t *argv);

//! Destroy action data allocated with pi_action_data_allocate
pi_status_t pi_action_data_destroy(pi_action_data_t *action_data);

#endif  // PI_INC_PI_FRONTENDS_GENERIC_PI_H_
