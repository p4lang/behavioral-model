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

#ifndef PI_SRC_P4INFO_ACT_PROFS_INT_H_
#define PI_SRC_P4INFO_ACT_PROFS_INT_H_

#include "PI/p4info/act_profs.h"

#ifdef __cplusplus
extern "C" {
#endif

void pi_p4info_act_prof_init(pi_p4info_t *p4info, size_t num_act_profs);

void pi_p4info_act_prof_free(pi_p4info_t *p4info);

void pi_p4info_act_prof_add(pi_p4info_t *p4info, pi_p4_id_t act_prof_id,
                            const char *name, bool with_selector,
                            size_t max_size);

void pi_p4info_act_prof_add_table(pi_p4info_t *p4info, pi_p4_id_t act_prof_id,
                                  pi_p4_id_t table_id);

void pi_p4info_act_prof_set_max_grp_size(pi_p4info_t *p4info,
                                         pi_p4_id_t act_prof_id,
                                         size_t max_grp_size);

#ifdef __cplusplus
}
#endif

#endif  // PI_SRC_P4INFO_ACT_PROFS_INT_H_
