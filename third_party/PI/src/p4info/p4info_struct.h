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

#ifndef PI_SRC_P4INFO_P4INFO_STRUCT_H_
#define PI_SRC_P4INFO_P4INFO_STRUCT_H_

#include <PI/int/pi_int.h>
#include "vector.h"

#include <stddef.h>

#include "p4info_common.h"
#include "p4info_name_map.h"
#include "vector.h"

typedef struct cJSON cJSON;

typedef void (*P4InfoSerializeFn)(cJSON *root, const pi_p4info_t *p4info);

// best that we can do?
typedef const char *(*P4InfoRetrieveNameFn)(const void *);

struct p4info_common_s {
  vector_t *annotations;
  vector_t *aliases;
};

typedef struct p4info_id_hash_s p4info_id_hash_t;

typedef VectorCleanFn P4InfoFreeOneFn;

typedef struct {
  int is_init;
  P4InfoRetrieveNameFn retrieve_name_fn;
  P4InfoFreeOneFn free_fn;
  P4InfoSerializeFn serialize_fn;
  // the objects live in the vector, the map is just a way to access them by id
  // without iterating through the vector
  p4info_id_hash_t *id_map;
  vector_t *vec;
  p4info_name_map_t name_map;
} pi_p4info_res_t;

struct pi_p4info_s {
  pi_p4info_res_t resources[PI_RES_TYPE_MAX];

  // for convenience, maybe remove later
  pi_p4info_res_t *actions;
  pi_p4info_res_t *tables;
  pi_p4info_res_t *act_profs;
  pi_p4info_res_t *counters;
  pi_p4info_res_t *direct_counters;
  pi_p4info_res_t *meters;
  pi_p4info_res_t *direct_meters;
  pi_p4info_res_t *digests;
};

static inline size_t num_res(const pi_p4info_t *p4info,
                             pi_res_type_id_t res_type) {
  const pi_p4info_res_t *res = &p4info->resources[res_type];
  if (!res->is_init) return 0;
  return vector_size(res->vec);
}

void *p4info_get_at(const pi_p4info_t *p4info, pi_p4_id_t id);

void p4info_init_res(pi_p4info_t *p4info, pi_res_type_id_t res_type, size_t num,
                     size_t e_size, P4InfoRetrieveNameFn retrieve_name_fn,
                     P4InfoFreeOneFn free_fn, P4InfoSerializeFn serialize_fn);

void p4info_struct_destroy(pi_p4info_t *p4info);

void *p4info_add_res(pi_p4info_t *p4info, pi_p4_id_t id, const char *name);

#endif  // PI_SRC_P4INFO_P4INFO_STRUCT_H_
