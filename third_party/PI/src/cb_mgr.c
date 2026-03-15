/* Copyright 2019-present Barefoot Networks, Inc.
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

#include "_assert.h"
#include "device_map.h"

#include <stdlib.h>

#include "cb_mgr.h"

void cb_mgr_init(cb_mgr_t *cb_mgr) {
  device_map_create(&cb_mgr->device_cbs);
  cb_mgr->default_cb.cb = NULL;
  cb_mgr->default_cb.cookie = NULL;
}

void cb_mgr_destroy(cb_mgr_t *cb_mgr) {
  device_map_destroy(&cb_mgr->device_cbs);
}

const cb_data_t *cb_mgr_get(cb_mgr_t *cb_mgr, pi_dev_id_t dev_id) {
  return (const cb_data_t *)device_map_get(&cb_mgr->device_cbs, dev_id);
}

void cb_mgr_add(cb_mgr_t *cb_mgr, pi_dev_id_t dev_id, GenericFnPtr cb,
                void *cb_cookie) {
  cb_data_t *cb_data = (cb_data_t *)device_map_get(&cb_mgr->device_cbs, dev_id);
  if (cb_data == NULL) {
    cb_data = malloc(sizeof(cb_data_t));
    _PI_ASSERT(device_map_add(&cb_mgr->device_cbs, dev_id, cb_data));
  }
  cb_data->cb = cb;
  cb_data->cookie = cb_cookie;
}

void cb_mgr_rm(cb_mgr_t *cb_mgr, pi_dev_id_t dev_id) {
  cb_data_t *cb_data = (cb_data_t *)device_map_get(&cb_mgr->device_cbs, dev_id);
  if (cb_data != NULL) {
    _PI_ASSERT(device_map_remove(&cb_mgr->device_cbs, dev_id));
    free(cb_data);
  }
}

const cb_data_t *cb_mgr_get_default(cb_mgr_t *cb_mgr) {
  return &cb_mgr->default_cb;
}

void cb_mgr_set_default(cb_mgr_t *cb_mgr, GenericFnPtr cb, void *cb_cookie) {
  cb_mgr->default_cb.cb = cb;
  cb_mgr->default_cb.cookie = cb_cookie;
}

void cb_mgr_reset_default(cb_mgr_t *cb_mgr) {
  cb_mgr->default_cb.cb = NULL;
  cb_mgr->default_cb.cookie = NULL;
}

const cb_data_t *cb_mgr_get_or_default(cb_mgr_t *cb_mgr, pi_dev_id_t dev_id) {
  const cb_data_t *cb_data = NULL;
  cb_data = cb_mgr_get(cb_mgr, dev_id);
  if (cb_data != NULL) return cb_data;
  cb_data = cb_mgr_get_default(cb_mgr);
  return (cb_data->cb == NULL) ? NULL : cb_data;
}
