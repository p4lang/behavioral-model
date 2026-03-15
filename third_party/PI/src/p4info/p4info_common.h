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

#ifndef PI_SRC_P4INFO_P4INFO_COMMON_H_
#define PI_SRC_P4INFO_P4INFO_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct p4info_common_s p4info_common_t;

void p4info_common_push_back_annotation(p4info_common_t *common,
                                        const char *annotation);

char const *const *p4info_common_annotations(p4info_common_t *common,
                                             size_t *num_annotations);

void p4info_common_push_back_alias(p4info_common_t *common, const char *alias);

char const *const *p4info_common_aliases(p4info_common_t *common,
                                         size_t *num_aliases);

typedef struct cJSON cJSON;
void p4info_common_serialize(cJSON *object, const p4info_common_t *common);

void p4info_common_init(p4info_common_t *common);

void p4info_common_destroy(p4info_common_t *common);

#ifdef __cplusplus
}
#endif

#endif  // PI_SRC_P4INFO_P4INFO_COMMON_H_
