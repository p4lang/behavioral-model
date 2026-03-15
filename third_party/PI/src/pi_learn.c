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

#include <PI/pi_learn.h>
#include <PI/target/pi_learn_imp.h>
#include "_assert.h"
#include "pi_learn_int.h"

#include <pthread.h>
#include <stdlib.h>

#include "cb_mgr.h"

static cb_mgr_t cb_mgr;
static pthread_mutex_t cb_mutex;

pi_status_t pi_learn_init() {
  if (pthread_mutex_init(&cb_mutex, NULL)) return PI_STATUS_PTHREAD_ERROR;
  cb_mgr_init(&cb_mgr);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_destroy() {
  if (pthread_mutex_destroy(&cb_mutex)) return PI_STATUS_PTHREAD_ERROR;
  cb_mgr_destroy(&cb_mgr);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_assign_device(pi_dev_id_t dev_id) {
  (void)dev_id;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_remove_device(pi_dev_id_t dev_id) {
  return pi_learn_deregister_cb(dev_id);
}

pi_status_t pi_learn_register_cb(pi_dev_id_t dev_id, PILearnCb cb,
                                 void *cb_cookie) {
  pthread_mutex_lock(&cb_mutex);
  cb_mgr_add(&cb_mgr, dev_id, (GenericFnPtr)cb, cb_cookie);
  pthread_mutex_unlock(&cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_register_default_cb(PILearnCb cb, void *cb_cookie) {
  pthread_mutex_lock(&cb_mutex);
  cb_mgr_set_default(&cb_mgr, (GenericFnPtr)cb, cb_cookie);
  pthread_mutex_unlock(&cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_deregister_cb(pi_dev_id_t dev_id) {
  pthread_mutex_lock(&cb_mutex);
  cb_mgr_rm(&cb_mgr, dev_id);
  pthread_mutex_unlock(&cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_deregister_default_cb() {
  pthread_mutex_lock(&cb_mutex);
  cb_mgr_reset_default(&cb_mgr);
  pthread_mutex_unlock(&cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_config_set(pi_session_handle_t session_handle,
                                pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                                const pi_learn_config_t *config) {
  return _pi_learn_config_set(session_handle, dev_id, learn_id, config);
}

pi_status_t pi_learn_msg_ack(pi_session_handle_t session_handle,
                             pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                             pi_learn_msg_id_t msg_id) {
  return _pi_learn_msg_ack(session_handle, dev_id, learn_id, msg_id);
}

pi_status_t pi_learn_msg_done(pi_learn_msg_t *msg) {
  return _pi_learn_msg_done(msg);
}

// called by backend
pi_status_t pi_learn_new_msg(pi_learn_msg_t *msg) {
  pi_dev_id_t dev_id = msg->dev_tgt.dev_id;
  pthread_mutex_lock(&cb_mutex);
  const cb_data_t *cb_data = cb_mgr_get_or_default(&cb_mgr, dev_id);
  if (cb_data) {
    ((PILearnCb)(cb_data->cb))(msg, cb_data->cookie);
    pthread_mutex_unlock(&cb_mutex);
    return PI_STATUS_SUCCESS;
  }
  pthread_mutex_unlock(&cb_mutex);
  return PI_STATUS_LEARN_NO_MATCHING_CB;
}
