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

#include "PI/p4info/counters.h"
#include "PI/int/pi_int.h"
#include "counters_int.h"
#include "p4info/p4info_struct.h"

#include <cJSON/cJSON.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct _counter_data_s {
  p4info_common_t common;
  char *name;
  pi_p4_id_t counter_id;
  pi_p4_id_t direct_table;                // PI_INVALID_ID if not direct
  pi_p4info_counter_unit_t counter_unit;  // mostly ignored
  size_t size;
} _counter_data_t;

static _counter_data_t *get_counter(const pi_p4info_t *p4info,
                                    pi_p4_id_t counter_id) {
  assert(PI_GET_TYPE_ID(counter_id) == PI_COUNTER_ID ||
         PI_GET_TYPE_ID(counter_id) == PI_DIRECT_COUNTER_ID);
  return p4info_get_at(p4info, counter_id);
}

static const char *retrieve_name(const void *data) {
  const _counter_data_t *counter = (const _counter_data_t *)data;
  return counter->name;
}

static void free_counter_data(void *data) {
  _counter_data_t *counter = (_counter_data_t *)data;
  if (!counter->name) return;
  free(counter->name);
  p4info_common_destroy(&counter->common);
}

static void counter_serialize(cJSON *root, const vector_t *counters,
                              const char *node_name) {
  cJSON *cArray = cJSON_CreateArray();
  for (size_t i = 0; i < vector_size(counters); i++) {
    _counter_data_t *counter = vector_at(counters, i);
    cJSON *cObject = cJSON_CreateObject();

    cJSON_AddStringToObject(cObject, "name", counter->name);
    cJSON_AddNumberToObject(cObject, "id", counter->counter_id);
    cJSON_AddNumberToObject(cObject, "direct_table", counter->direct_table);
    cJSON_AddNumberToObject(cObject, "counter_unit", counter->counter_unit);
    cJSON_AddNumberToObject(cObject, "size", counter->size);

    p4info_common_serialize(cObject, &counter->common);

    cJSON_AddItemToArray(cArray, cObject);
  }
  cJSON_AddItemToObject(root, node_name, cArray);
}

static void pi_p4info_counter_serialize(cJSON *root,
                                        const pi_p4info_t *p4info) {
  const vector_t *counters = p4info->counters->vec;
  counter_serialize(root, counters, "counters");
}

static void pi_p4info_direct_counter_serialize(cJSON *root,
                                               const pi_p4info_t *p4info) {
  const vector_t *direct_counters = p4info->direct_counters->vec;
  counter_serialize(root, direct_counters, "direct_counters");
}

void pi_p4info_counter_init(pi_p4info_t *p4info, size_t num_counters) {
  p4info_init_res(p4info, PI_COUNTER_ID, num_counters, sizeof(_counter_data_t),
                  retrieve_name, free_counter_data,
                  pi_p4info_counter_serialize);
}

void pi_p4info_direct_counter_init(pi_p4info_t *p4info,
                                   size_t num_direct_counters) {
  p4info_init_res(p4info, PI_DIRECT_COUNTER_ID, num_direct_counters,
                  sizeof(_counter_data_t), retrieve_name, free_counter_data,
                  pi_p4info_direct_counter_serialize);
}

static _counter_data_t *counter_add(pi_p4info_t *p4info, pi_p4_id_t counter_id,
                                    const char *name,
                                    pi_p4info_counter_unit_t counter_unit,
                                    size_t size) {
  char *name_copy = strdup(name);
  _counter_data_t *counter = p4info_add_res(p4info, counter_id, name_copy);
  counter->name = name_copy;
  counter->counter_id = counter_id;
  counter->counter_unit = counter_unit;
  counter->direct_table = PI_INVALID_ID;
  counter->size = size;
  return counter;
}

void pi_p4info_counter_add(pi_p4info_t *p4info, pi_p4_id_t counter_id,
                           const char *name,
                           pi_p4info_counter_unit_t counter_unit, size_t size) {
  counter_add(p4info, counter_id, name, counter_unit, size);
}

void pi_p4info_direct_counter_add(pi_p4info_t *p4info, pi_p4_id_t counter_id,
                                  const char *name,
                                  pi_p4info_counter_unit_t counter_unit,
                                  size_t size, pi_p4_id_t direct_table_id) {
  _counter_data_t *counter =
      counter_add(p4info, counter_id, name, counter_unit, size);
  counter->direct_table = direct_table_id;
}

pi_p4_id_t pi_p4info_counter_id_from_name(const pi_p4info_t *p4info,
                                          const char *name) {
  // TODO(antonin): ugly hack so that we can keep a unique function to query the
  // id of a counter. In P4_16 all objects are guaranteed to have unique names,
  // so maybe we could keep a single name map for all objects instead of having
  // a map per resource type (but then what about aliases?).
  pi_p4_id_t id = p4info_name_map_get(&p4info->counters->name_map, name);
  if (id != PI_INVALID_ID) return id;
  return p4info_name_map_get(&p4info->direct_counters->name_map, name);
}

const char *pi_p4info_counter_name_from_id(const pi_p4info_t *p4info,
                                           pi_p4_id_t counter_id) {
  _counter_data_t *counter = get_counter(p4info, counter_id);
  return counter->name;
}

pi_p4_id_t pi_p4info_counter_get_direct(const pi_p4info_t *p4info,
                                        pi_p4_id_t counter_id) {
  _counter_data_t *counter = get_counter(p4info, counter_id);
  return counter->direct_table;
}

pi_p4info_counter_unit_t pi_p4info_counter_get_unit(const pi_p4info_t *p4info,
                                                    pi_p4_id_t counter_id) {
  _counter_data_t *counter = get_counter(p4info, counter_id);
  return counter->counter_unit;
}

size_t pi_p4info_counter_get_size(const pi_p4info_t *p4info,
                                  pi_p4_id_t counter_id) {
  _counter_data_t *counter = get_counter(p4info, counter_id);
  return counter->size;
}

pi_p4_id_t pi_p4info_counter_begin(const pi_p4info_t *p4info) {
  return pi_p4info_any_begin(p4info, PI_COUNTER_ID);
}

pi_p4_id_t pi_p4info_counter_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  return pi_p4info_any_next(p4info, id);
}

pi_p4_id_t pi_p4info_counter_end(const pi_p4info_t *p4info) {
  return pi_p4info_any_end(p4info, PI_COUNTER_ID);
}

pi_p4_id_t pi_p4info_direct_counter_begin(const pi_p4info_t *p4info) {
  return pi_p4info_any_begin(p4info, PI_DIRECT_COUNTER_ID);
}

pi_p4_id_t pi_p4info_direct_counter_next(const pi_p4info_t *p4info,
                                         pi_p4_id_t id) {
  return pi_p4info_any_next(p4info, id);
}

pi_p4_id_t pi_p4info_direct_counter_end(const pi_p4info_t *p4info) {
  return pi_p4info_any_end(p4info, PI_DIRECT_COUNTER_ID);
}
