/* Copyright 2018-present Barefoot Networks, Inc.
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
//! Functions to query digest information in a p4info object.

#ifndef PI_INC_PI_P4INFO_DIGESTS_H_
#define PI_INC_PI_P4INFO_DIGESTS_H_

#include "PI/pi_base.h"

#ifdef __cplusplus
extern "C" {
#endif

size_t pi_p4info_digest_get_num(const pi_p4info_t *p4info);

pi_p4_id_t pi_p4info_digest_id_from_name(const pi_p4info_t *p4info,
                                         const char *name);

const char *pi_p4info_digest_name_from_id(const pi_p4info_t *p4info,
                                          pi_p4_id_t digest_id);

size_t pi_p4info_digest_num_fields(const pi_p4info_t *p4info,
                                   pi_p4_id_t digest_id);

const char *pi_p4info_digest_field_name(const pi_p4info_t *p4info,
                                        pi_p4_id_t digest_id, size_t idx);

size_t pi_p4info_digest_field_bitwidth(const pi_p4info_t *p4info,
                                       pi_p4_id_t digest_id, size_t idx);

size_t pi_p4info_digest_data_size(const pi_p4info_t *p4info,
                                  pi_p4_id_t digest_id);

pi_p4_id_t pi_p4info_digest_begin(const pi_p4info_t *p4info);
pi_p4_id_t pi_p4info_digest_next(const pi_p4info_t *p4info, pi_p4_id_t id);
pi_p4_id_t pi_p4info_digest_end(const pi_p4info_t *p4info);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_P4INFO_DIGESTS_H_
