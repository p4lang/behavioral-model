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

#ifndef PI_SRC_P4INFO_DIGESTS_INT_H_
#define PI_SRC_P4INFO_DIGESTS_INT_H_

#include "PI/p4info/digests.h"

#include "p4info_common.h"

#ifdef __cplusplus
extern "C" {
#endif

void pi_p4info_digest_init(pi_p4info_t *p4info, size_t num_digests);

void pi_p4info_digest_add(pi_p4info_t *p4info, pi_p4_id_t digest_id,
                          const char *name, size_t num_fields);

void pi_p4info_digest_add_field(pi_p4info_t *p4info, pi_p4_id_t digest_id,
                                const char *name, size_t bitwidth);

#ifdef __cplusplus
}
#endif

#endif  // PI_SRC_P4INFO_DIGESTS_INT_H_
