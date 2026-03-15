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
//! Functions to query meter information in a p4info object.

#ifndef PI_INC_PI_P4INFO_METERS_H_
#define PI_INC_PI_P4INFO_METERS_H_

#include <PI/pi_base.h>

#ifdef __cplusplus
extern "C" {
#endif

// same as their PI equivalent, without the default option
typedef enum {
  PI_P4INFO_METER_UNIT_PACKETS = 1,
  PI_P4INFO_METER_UNIT_BYTES = 2,
} pi_p4info_meter_unit_t;

typedef enum {
  PI_P4INFO_METER_TYPE_COLOR_AWARE = 1,
  PI_P4INFO_METER_TYPE_COLOR_UNAWARE = 2,
} pi_p4info_meter_type_t;

pi_p4_id_t pi_p4info_meter_id_from_name(const pi_p4info_t *p4info,
                                        const char *name);

const char *pi_p4info_meter_name_from_id(const pi_p4info_t *p4info,
                                         pi_p4_id_t meter_id);

pi_p4_id_t pi_p4info_meter_get_direct(const pi_p4info_t *p4info,
                                      pi_p4_id_t meter_id);

pi_p4info_meter_unit_t pi_p4info_meter_get_unit(const pi_p4info_t *p4info,
                                                pi_p4_id_t meter_id);

pi_p4info_meter_type_t pi_p4info_meter_get_type(const pi_p4info_t *p4info,
                                                pi_p4_id_t meter_id);

size_t pi_p4info_meter_get_size(const pi_p4info_t *p4info, pi_p4_id_t meter_id);

pi_p4_id_t pi_p4info_meter_begin(const pi_p4info_t *p4info);
pi_p4_id_t pi_p4info_meter_next(const pi_p4info_t *p4info, pi_p4_id_t id);
pi_p4_id_t pi_p4info_meter_end(const pi_p4info_t *p4info);

pi_p4_id_t pi_p4info_direct_meter_begin(const pi_p4info_t *p4info);
pi_p4_id_t pi_p4info_direct_meter_next(const pi_p4info_t *p4info,
                                       pi_p4_id_t id);
pi_p4_id_t pi_p4info_direct_meter_end(const pi_p4info_t *p4info);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_P4INFO_METERS_H_
