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

#include "vector.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_INIT_CAPACITY 16

struct vector_s {
  size_t e_size;
  size_t size;
  size_t capacity;
  void *data;
  VectorCleanFn clean_fn;
};

vector_t *vector_create_wclean(size_t e_size, size_t init_capacity,
                               VectorCleanFn clean_fn) {
  assert(e_size > 0);
  if (init_capacity == 0) init_capacity = DEFAULT_INIT_CAPACITY;
  vector_t *v = malloc(sizeof(vector_t));
  v->e_size = e_size;
  v->size = 0;
  v->capacity = init_capacity;
  v->data = malloc(init_capacity * e_size);
  v->clean_fn = clean_fn;
  return v;
}

vector_t *vector_create(size_t e_size, size_t init_capacity) {
  return vector_create_wclean(e_size, init_capacity, NULL);
}

static void vector_expand(vector_t *v) {
  v->capacity *= 2;
  v->data = realloc(v->data, v->capacity * v->e_size);
}

static void *access_element(const vector_t *v, size_t index) {
  return (char *)v->data + (index * v->e_size);
}

void vector_push_back_empty(vector_t *v) {
  assert(v->size <= v->capacity);
  if (v->size == v->capacity) vector_expand(v);
  memset(access_element(v, v->size), 0, v->e_size);
  v->size++;
}

void vector_push_back(vector_t *v, void *e) {
  assert(v->size <= v->capacity);
  if (v->size == v->capacity) vector_expand(v);
  memcpy(access_element(v, v->size), e, v->e_size);
  v->size++;
}

void *vector_at(const vector_t *v, size_t index) {
  assert(index < v->size);
  return access_element(v, index);
}

void *vector_data(const vector_t *v) { return v->data; }

size_t vector_size(const vector_t *v) { return v->size; }

void vector_remove(vector_t *v, size_t index) {
  assert(index < v->size);
  v->size--;
  if (index == v->size) return;
  memmove(access_element(v, index), access_element(v, index + 1),
          (v->size - index) * v->e_size);
}

void vector_remove_e(vector_t *v, void *e) {
  assert(e >= v->data);
  size_t index = (char *)e - (char *)v->data;
  vector_remove(v, index);
}

void vector_destroy(vector_t *v) {
  if (v->clean_fn) {
    for (size_t index = 0; index < v->size; index++) {
      v->clean_fn(access_element(v, index));
    }
  }
  free(v->data);
  free(v);
}

void *vector_back(vector_t *v) {
  if (v->size == 0) return NULL;
  return access_element(v, v->size - 1);
}
