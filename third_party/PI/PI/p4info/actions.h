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
//! Functions to query action information in a p4info object.

#ifndef PI_INC_PI_P4INFO_ACTIONS_H_
#define PI_INC_PI_P4INFO_ACTIONS_H_

#include "PI/pi_base.h"

#ifdef __cplusplus
extern "C" {
#endif

size_t pi_p4info_action_get_num(const pi_p4info_t *p4info);

pi_p4_id_t pi_p4info_action_id_from_name(const pi_p4info_t *p4info,
                                         const char *name);

const char *pi_p4info_action_name_from_id(const pi_p4info_t *p4info,
                                          pi_p4_id_t action_id);

size_t pi_p4info_action_num_params(const pi_p4info_t *p4info,
                                   pi_p4_id_t action_id);

const pi_p4_id_t *pi_p4info_action_get_params(const pi_p4info_t *p4info,
                                              pi_p4_id_t action_id,
                                              size_t *num_params);

pi_p4_id_t pi_p4info_action_param_id_from_name(const pi_p4info_t *p4info,
                                               pi_p4_id_t action_id,
                                               const char *name);

const char *pi_p4info_action_param_name_from_id(const pi_p4info_t *p4info,
                                                pi_p4_id_t action_id,
                                                pi_p4_id_t param_id);

size_t pi_p4info_action_param_index(const pi_p4info_t *p4info,
                                    pi_p4_id_t action_id, pi_p4_id_t param_id);

size_t pi_p4info_action_param_bitwidth(const pi_p4info_t *p4info,
                                       pi_p4_id_t action_id,
                                       pi_p4_id_t param_id);

char pi_p4info_action_param_byte0_mask(const pi_p4info_t *p4info,
                                       pi_p4_id_t action_id,
                                       pi_p4_id_t param_id);

size_t pi_p4info_action_param_offset(const pi_p4info_t *p4info,
                                     pi_p4_id_t action_id, pi_p4_id_t param_id);

size_t pi_p4info_action_data_size(const pi_p4info_t *p4info,
                                  pi_p4_id_t action_id);

pi_p4_id_t pi_p4info_action_begin(const pi_p4info_t *p4info);
pi_p4_id_t pi_p4info_action_next(const pi_p4info_t *p4info, pi_p4_id_t id);
pi_p4_id_t pi_p4info_action_end(const pi_p4info_t *p4info);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_P4INFO_ACTIONS_H_
