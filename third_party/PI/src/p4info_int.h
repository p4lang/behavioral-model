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

#ifndef PI_SRC_P4INFO_INT_H_
#define PI_SRC_P4INFO_INT_H_

#include "p4info/act_profs_int.h"
#include "p4info/actions_int.h"
#include "p4info/counters_int.h"
#include "p4info/digests_int.h"
#include "p4info/meters_int.h"
#include "p4info/tables_int.h"

#ifdef __cplusplus
extern "C" {
#endif

pi_status_t pi_p4info_add_alias(pi_p4info_t *p4info, pi_p4_id_t id,
                                const char *alias);

char const *const *pi_p4info_get_aliases(const pi_p4info_t *p4info,
                                         pi_p4_id_t id, size_t *num_aliases);

pi_status_t pi_p4info_add_annotation(pi_p4info_t *p4info, pi_p4_id_t id,
                                     const char *annotation);

char const *const *pi_p4info_get_annotations(const pi_p4info_t *p4info,
                                             pi_p4_id_t id,
                                             size_t *num_annotations);

#ifdef __cplusplus
}
#endif

#endif  // PI_SRC_P4INFO_INT_H_
