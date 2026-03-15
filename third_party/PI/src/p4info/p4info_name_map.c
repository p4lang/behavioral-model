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

#include "p4info_name_map.h"

#include <uthash.h>

struct p4info_name_hash_s {
  const char *name;
  pi_p4_id_t id;
  UT_hash_handle hh;
};

void p4info_name_map_init(p4info_name_map_t *map) { map->hash = NULL; }

int p4info_name_map_add(p4info_name_map_t *map, const char *name,
                        pi_p4_id_t id) {
  p4info_name_hash_t *hash;
  HASH_FIND_STR(map->hash, name, hash);
  if (hash) return 0;
  hash = malloc(sizeof(*hash));
  hash->name = name;
  hash->id = id;
  HASH_ADD_KEYPTR(hh, map->hash, hash->name, strlen(hash->name), hash);
  return 1;
}

pi_p4_id_t p4info_name_map_get(const p4info_name_map_t *map, const char *name) {
  p4info_name_hash_t *hash;
  HASH_FIND_STR(map->hash, name, hash);
  return (hash) ? hash->id : PI_INVALID_ID;
}

void p4info_name_map_destroy(p4info_name_map_t *map) {
  p4info_name_hash_t *hash, *tmp;
  HASH_ITER(hh, map->hash, hash, tmp) {  // deletion-safe iteration
    HASH_DEL(map->hash, hash);
    free(hash);
  }
}
