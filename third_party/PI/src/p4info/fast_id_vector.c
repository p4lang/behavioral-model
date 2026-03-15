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

#include "fast_id_vector.h"

#include <stdlib.h>
#include <string.h>

void id_vector_init(id_vector_t *id_vector) {
  id_vector->size = 0;
  id_vector->capacity = 0;
}

void id_vector_push_back(id_vector_t *id_vector, pi_p4_id_t id) {
  if (id_vector->size < ID_VECTOR_INLINE_IDS) {
    id_vector->ids.direct[id_vector->size] = id;
  } else if (id_vector->size > ID_VECTOR_INLINE_IDS) {
    if (id_vector->size >= id_vector->capacity) {
      id_vector->capacity *= 2;
      id_vector->ids.indirect = realloc(
          id_vector->ids.indirect, id_vector->capacity * sizeof(pi_p4_id_t));
    }
    id_vector->ids.indirect[id_vector->size] = id;
  } else {
    id_vector->capacity = 2 * ID_VECTOR_INLINE_IDS;
    pi_p4_id_t *ids = malloc(id_vector->capacity * sizeof(pi_p4_id_t));
    memcpy(ids, id_vector->ids.direct, sizeof(id_vector->ids.direct));
    id_vector->ids.indirect = ids;
    id_vector->ids.indirect[id_vector->size] = id;
  }
  id_vector->size += 1;
}

void id_vector_destroy(id_vector_t *id_vector) {
  if (id_vector->size > ID_VECTOR_INLINE_IDS) free(id_vector->ids.indirect);
}
