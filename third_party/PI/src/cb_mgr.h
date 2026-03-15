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

#ifndef PI_SRC_CB_MGR_H_
#define PI_SRC_CB_MGR_H_

#include "device_map.h"

typedef void (*GenericFnPtr)();

typedef struct {
  GenericFnPtr cb;
  void *cookie;
} cb_data_t;

typedef struct {
  device_map_t device_cbs;
  cb_data_t default_cb;
} cb_mgr_t;

void cb_mgr_init(cb_mgr_t *cb_mgr);

void cb_mgr_destroy(cb_mgr_t *cb_mgr);

const cb_data_t *cb_mgr_get(cb_mgr_t *cb_mgr, pi_dev_id_t dev_id);

void cb_mgr_add(cb_mgr_t *cb_mgr, pi_dev_id_t dev_id, GenericFnPtr cb,
                void *cb_cookie);

void cb_mgr_rm(cb_mgr_t *cb_mgr, pi_dev_id_t dev_id);

const cb_data_t *cb_mgr_get_default(cb_mgr_t *cb_mgr);

void cb_mgr_set_default(cb_mgr_t *cb_mgr, GenericFnPtr cb, void *cb_cookie);

void cb_mgr_reset_default(cb_mgr_t *cb_mgr);

const cb_data_t *cb_mgr_get_or_default(cb_mgr_t *cb_mgr, pi_dev_id_t dev_id);

#endif  // PI_SRC_CB_MGR_H_
