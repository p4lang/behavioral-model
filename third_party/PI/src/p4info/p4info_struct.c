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

#include "p4info_struct.h"

#include <PI/p4info.h>
#include <uthash.h>

struct p4info_id_hash_s {
  pi_p4_id_t id;
  void *e;
  UT_hash_handle hh;
};

void p4info_init_res(pi_p4info_t *p4info, pi_res_type_id_t res_type, size_t num,
                     size_t e_size, P4InfoRetrieveNameFn retrieve_name_fn,
                     P4InfoFreeOneFn free_fn, P4InfoSerializeFn serialize_fn) {
  pi_p4info_res_t *res = &p4info->resources[res_type];
  res->is_init = 1;
  res->retrieve_name_fn = retrieve_name_fn;
  res->free_fn = free_fn;
  res->serialize_fn = serialize_fn;
  res->id_map = NULL;
  res->vec = vector_create_wclean(e_size, num, free_fn);
  p4info_name_map_init(&res->name_map);
}

void p4info_struct_destroy(pi_p4info_t *p4info) {
  for (size_t i = 0;
       i < sizeof(p4info->resources) / sizeof(p4info->resources[0]); i++) {
    pi_p4info_res_t *res = &p4info->resources[i];
    if (!res->is_init) continue;
    assert(res->free_fn);
    vector_destroy(res->vec);
    p4info_name_map_destroy(&res->name_map);
    // deletion-safe iteration
    p4info_id_hash_t *id_hash, *tmp;
    HASH_ITER(hh, res->id_map, id_hash, tmp) {
      HASH_DEL(res->id_map, id_hash);
      free(id_hash);
    }
  }
}

// C1x §6.7.2.1.13: "A pointer to a structure object, suitably converted, points
// to its initial member ... and vice versa. There may be unnamed padding within
// as structure object, but not at its beginning."
static p4info_common_t *pi_p4info_get_common(const pi_p4info_t *p4info,
                                             pi_p4_id_t id) {
  void *e = p4info_get_at(p4info, id);
  return (p4info_common_t *)e;
}

void *p4info_get_at(const pi_p4info_t *p4info, pi_p4_id_t id) {
  const pi_p4info_res_t *res = &p4info->resources[PI_GET_TYPE_ID(id)];
  p4info_id_hash_t *id_hash;
  id &= 0xFFFFFF;
  HASH_FIND(hh, res->id_map, &id, sizeof(id), id_hash);
  return id_hash->e;
}

void *p4info_add_res(pi_p4info_t *p4info, pi_p4_id_t id, const char *name) {
  pi_p4info_res_t *res = &p4info->resources[PI_GET_TYPE_ID(id)];
  p4info_name_map_add(&res->name_map, name, id);
  vector_push_back_empty(res->vec);
  void *new = vector_back(res->vec);
  p4info_common_init((p4info_common_t *)new);
  p4info_id_hash_t *id_hash;
  id &= 0xFFFFFF;
  HASH_FIND(hh, res->id_map, &id, sizeof(id), id_hash);
  // TODO(antonin): do something else besides overwriting in case of duplicate?
  // TODO(antonin): allocate contiguous memory for the hashes, for iteration?
  if (id_hash) {
    id_hash->e = new;
    return new;
  }
  id_hash = malloc(sizeof(*id_hash));
  id_hash->id = id;
  id_hash->e = new;
  HASH_ADD(hh, res->id_map, id, sizeof(id), id_hash);
  return new;
}

pi_p4_id_t pi_p4info_any_begin(const pi_p4info_t *p4info,
                               pi_res_type_id_t type) {
  const pi_p4info_res_t *res = &p4info->resources[type];
  if (!res->id_map) return PI_INVALID_ID;
  return (type << 24) | res->id_map->id;
}

pi_p4_id_t pi_p4info_any_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  pi_res_type_id_t type = PI_GET_TYPE_ID(id);
  const pi_p4info_res_t *res = &p4info->resources[type];
  p4info_id_hash_t *id_hash;
  id &= 0xFFFFFF;
  HASH_FIND(hh, res->id_map, &id, sizeof(id), id_hash);
  if (!id_hash) return PI_INVALID_ID;
  id_hash = id_hash->hh.next;
  return (id_hash) ? ((type << 24) | id_hash->id) : PI_INVALID_ID;
}

pi_p4_id_t pi_p4info_any_end(const pi_p4info_t *p4info, pi_res_type_id_t type) {
  (void)p4info;
  (void)type;
  return PI_INVALID_ID;
}

size_t pi_p4info_any_num(const pi_p4info_t *p4info, pi_res_type_id_t type) {
  return num_res(p4info, type);
}

const char *pi_p4info_any_name_from_id(const pi_p4info_t *p4info,
                                       pi_p4_id_t id) {
  const pi_p4info_res_t *res = &p4info->resources[PI_GET_TYPE_ID(id)];
  const void *data = p4info_get_at(p4info, id);
  return res->retrieve_name_fn(data);
}

pi_p4_id_t pi_p4info_any_id_from_name(const pi_p4info_t *p4info,
                                      pi_res_type_id_t type, const char *name) {
  const pi_p4info_res_t *res = &p4info->resources[type];
  return p4info_name_map_get(&res->name_map, name);
}

bool pi_p4info_is_valid_id(const pi_p4info_t *p4info, pi_p4_id_t id) {
  const pi_p4info_res_t *res = &p4info->resources[PI_GET_TYPE_ID(id)];
  if (!res->is_init) return false;
  p4info_id_hash_t *id_hash;
  id &= 0xFFFFFF;
  HASH_FIND(hh, res->id_map, &id, sizeof(id), id_hash);
  return (id_hash != NULL);
}

pi_status_t pi_p4info_add_alias(pi_p4info_t *p4info, pi_p4_id_t id,
                                const char *alias) {
  pi_p4info_res_t *res = &p4info->resources[PI_GET_TYPE_ID(id)];
  int rc = p4info_name_map_add(&res->name_map, alias, id);
  if (rc == 0) return PI_STATUS_ALIAS_ALREADY_EXISTS;
  p4info_common_push_back_alias(pi_p4info_get_common(p4info, id), alias);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_p4info_add_annotation(pi_p4info_t *p4info, pi_p4_id_t id,
                                     const char *annotation) {
  p4info_common_push_back_annotation(pi_p4info_get_common(p4info, id),
                                     annotation);
  return PI_STATUS_SUCCESS;
}

char const *const *pi_p4info_get_aliases(const pi_p4info_t *p4info,
                                         pi_p4_id_t id, size_t *num_aliases) {
  return p4info_common_aliases(pi_p4info_get_common(p4info, id), num_aliases);
}

char const *const *pi_p4info_get_annotations(const pi_p4info_t *p4info,
                                             pi_p4_id_t id,
                                             size_t *num_annotations) {
  return p4info_common_annotations(pi_p4info_get_common(p4info, id),
                                   num_annotations);
}
