/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
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
 * Antonin Bas
 *
 */

#ifndef PI_SRC_P4INFO_P4INFO_NAME_MAP_H_
#define PI_SRC_P4INFO_P4INFO_NAME_MAP_H_

#include <PI/pi_base.h>

typedef struct p4info_name_hash_s p4info_name_hash_t;

typedef struct {
  p4info_name_hash_t *hash;
} p4info_name_map_t;

void p4info_name_map_init(p4info_name_map_t *map);

// returns 1 if value succesfully inserted, 0 if key was already present
int p4info_name_map_add(p4info_name_map_t *map, const char *name,
                        pi_p4_id_t id);

pi_p4_id_t p4info_name_map_get(const p4info_name_map_t *map, const char *name);

void p4info_name_map_destroy(p4info_name_map_t *map);

#endif  // PI_SRC_P4INFO_P4INFO_NAME_MAP_H_
