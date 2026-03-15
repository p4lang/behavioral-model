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

#ifndef PI_SRC_P4INFO_FAST_ID_VECTOR_H_
#define PI_SRC_P4INFO_FAST_ID_VECTOR_H_

#include <PI/pi_base.h>

#include <stddef.h>

// A vector of ids optimized for p4info. The vector can only grow and ids are
// stored inline until a limit is reached, at which point they are relocated to
// some new memory.

#define ID_VECTOR_INLINE_IDS 8

typedef struct id_vector_s {
  size_t size;
  size_t capacity;
  union {
    pi_p4_id_t *indirect;
    pi_p4_id_t direct[ID_VECTOR_INLINE_IDS];
  } ids;
} id_vector_t;

void id_vector_init(id_vector_t *id_vector);

#define ID_VECTOR_INIT(vec) id_vector_init(&vec);

void id_vector_push_back(id_vector_t *id_vector, pi_p4_id_t id);

#define ID_VECTOR_PUSH_BACK(vec, id) id_vector_push_back(&vec, id);

#define ID_VECTOR_GET(vec) \
  ((vec.size <= ID_VECTOR_INLINE_IDS) ? vec.ids.direct : vec.ids.indirect)

#define ID_VECTOR_NUM(vec) (vec.size)

void id_vector_destroy(id_vector_t *id_vector);

#define ID_VECTOR_DESTROY(vec) id_vector_destroy(&vec);

#endif  // PI_SRC_P4INFO_FAST_ID_VECTOR_H_
