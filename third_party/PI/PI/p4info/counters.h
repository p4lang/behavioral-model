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
//! Functions to query counter information in a p4info object.

#ifndef PI_INC_PI_P4INFO_COUNTERS_H_
#define PI_INC_PI_P4INFO_COUNTERS_H_

#include <PI/pi_base.h>

#ifdef __cplusplus
extern "C" {
#endif

// TODO(antonin): remnant of P4_14, remove?
typedef enum {
  PI_P4INFO_COUNTER_UNIT_BYTES = 0,
  PI_P4INFO_COUNTER_UNIT_PACKETS,
  PI_P4INFO_COUNTER_UNIT_BOTH
} pi_p4info_counter_unit_t;

pi_p4_id_t pi_p4info_counter_id_from_name(const pi_p4info_t *p4info,
                                          const char *name);

const char *pi_p4info_counter_name_from_id(const pi_p4info_t *p4info,
                                           pi_p4_id_t counter_id);

pi_p4_id_t pi_p4info_counter_get_direct(const pi_p4info_t *p4info,
                                        pi_p4_id_t counter_id);

pi_p4info_counter_unit_t pi_p4info_counter_get_unit(const pi_p4info_t *p4info,
                                                    pi_p4_id_t counter_id);

size_t pi_p4info_counter_get_size(const pi_p4info_t *p4info,
                                  pi_p4_id_t counter_id);

pi_p4_id_t pi_p4info_counter_begin(const pi_p4info_t *p4info);
pi_p4_id_t pi_p4info_counter_next(const pi_p4info_t *p4info, pi_p4_id_t id);
pi_p4_id_t pi_p4info_counter_end(const pi_p4info_t *p4info);

pi_p4_id_t pi_p4info_direct_counter_begin(const pi_p4info_t *p4info);
pi_p4_id_t pi_p4info_direct_counter_next(const pi_p4info_t *p4info,
                                         pi_p4_id_t id);
pi_p4_id_t pi_p4info_direct_counter_end(const pi_p4info_t *p4info);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_P4INFO_COUNTERS_H_
