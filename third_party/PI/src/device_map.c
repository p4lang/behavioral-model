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

#include "device_map.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct device_entry_s {
  pi_dev_id_t dev_id;
  void *e;
};

void device_map_create(device_map_t *map) {
  map->size = 0;
  map->capacity = 8;  // initial capacity
  map->entries = malloc(map->capacity * sizeof(*map->entries));
}

static bool binary_search(device_map_t *map, pi_dev_id_t dev_id, int *idx) {
  int a = 0;
  int b = map->size;
  while (a < b) {
    *idx = a + (b - a) / 2;
    device_entry_t *entry = &map->entries[*idx];
    if (dev_id < entry->dev_id) {
      b = *idx;
    } else if (dev_id > entry->dev_id) {
      a = *idx + 1;
    } else {
      return true;
    }
  }
  *idx = a;
  return false;
}

bool device_map_add(device_map_t *map, pi_dev_id_t dev_id, void *e) {
  int idx;
  if (binary_search(map, dev_id, &idx)) return false;  // already exists
  if (map->size >= map->capacity) {
    map->capacity *= 2;
    map->entries = realloc(map->entries, map->capacity * sizeof(*map->entries));
  }
  // insert the new element at position "idx"
  size_t size = (map->size - idx) * sizeof(*map->entries);
  memmove(&map->entries[idx + 1], &map->entries[idx], size);
  map->entries[idx].dev_id = dev_id;
  map->entries[idx].e = e;
  map->size++;
  return true;
}

bool device_map_remove(device_map_t *map, pi_dev_id_t dev_id) {
  int idx;
  if (!binary_search(map, dev_id, &idx)) return false;  // not found
  // we do not free up memory when we shrink the vector
  size_t size = (map->size - idx - 1) * sizeof(*map->entries);
  memmove(&map->entries[idx], &map->entries[idx + 1], size);
  map->size--;
  return true;
}

bool device_map_exists(device_map_t *map, pi_dev_id_t dev_id) {
  int idx;
  return binary_search(map, dev_id, &idx);
}

void *device_map_get(device_map_t *map, pi_dev_id_t dev_id) {
  int idx;
  if (!binary_search(map, dev_id, &idx)) return NULL;
  return map->entries[idx].e;
}

void device_map_for_each(device_map_t *map, DeviceMapApplyFn fn, void *cookie) {
  for (int idx = 0; idx < map->size; idx++) {
    fn(map->entries[idx].e, cookie);
  }
}

size_t device_map_count(device_map_t *map) { return map->size; }

void device_map_destroy(device_map_t *map) { free(map->entries); }
