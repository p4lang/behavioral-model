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

#ifndef PI_SRC_DEVICE_MAP_H_
#define PI_SRC_DEVICE_MAP_H_

#include <PI/pi_base.h>

#include <stdbool.h>
#include <stddef.h>

typedef struct device_entry_s device_entry_t;

// This is actually a sorted vector, we expect the num of devices to be small.
typedef struct {
  device_entry_t *entries;
  int size;
  int capacity;
} device_map_t;

void device_map_create(device_map_t *map);

// returns false if device already exists
bool device_map_add(device_map_t *map, pi_dev_id_t dev_id, void *e);

// returns false if device does not exists
bool device_map_remove(device_map_t *map, pi_dev_id_t dev_id);

bool device_map_exists(device_map_t *map, pi_dev_id_t dev_id);

// returns NULL if device does not exists
void *device_map_get(device_map_t *map, pi_dev_id_t dev_id);

typedef void (*DeviceMapApplyFn)(void *e, void *cookie);

void device_map_for_each(device_map_t *map, DeviceMapApplyFn fn, void *cookie);

size_t device_map_count(device_map_t *map);

void device_map_destroy(device_map_t *map);

#endif  // PI_SRC_DEVICE_MAP_H_
