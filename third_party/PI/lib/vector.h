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

#ifndef PI_TOOLKIT_VECTOR_H_
#define PI_TOOLKIT_VECTOR_H_

#include <stddef.h>

typedef struct vector_s vector_t;

vector_t *vector_create(size_t e_size, size_t init_capacity);

typedef void (*VectorCleanFn)(void *e);

vector_t *vector_create_wclean(size_t e_size, size_t init_capacity,
                               VectorCleanFn clean_fn);

void vector_destroy(vector_t *v);

void vector_push_back(vector_t *v, void *e);

// add an element at the end, with memory initialized to 0
void vector_push_back_empty(vector_t *v);

void *vector_at(const vector_t *v, size_t index);

void *vector_data(const vector_t *v);

size_t vector_size(const vector_t *v);

void vector_remove(vector_t *v, size_t index);

void vector_remove_e(vector_t *v, void *e);

void *vector_back(vector_t *v);

/* typedef int (*VectorCmpFn)(const void *e1, const void *e2); */
/* void *vector_search(vector_t *v, VectorCmpFn cmp_fn, size_t start_index); */

#endif  // PI_TOOLKIT_VECTOR_H_
