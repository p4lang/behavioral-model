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

#include "PI/pi.h"
#include "PI/int/pi_int.h"
#include "PI/int/serialize.h"
#include "PI/target/pi_imp.h"
#include "_assert.h"
#include "cb_mgr.h"
#include "device_map.h"
#include "pi_learn_int.h"
#include "pi_tables_int.h"
#include "utils/logging.h"
#include "vector.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static device_map_t device_map;
static vector_t *device_arr = NULL;

// protects access to device_map and device_arr
// client can manage mutex itself by calling pi_device_lock() /
// pi_device_unlock() which is useful when a function (e.g. pi_get_devices())
// returns a pointer offering direct access to shared state
// these functions are for internal library use only (they are declared in
// PI/int/pi_int.h)
static pthread_mutex_t device_map_mutex;

typedef struct {
  int is_set;
  PIDirectResMsgSizeFn msg_size_fn;
  PIDirectResEmitFn emit_fn;
  size_t size_of;
  PIDirectResRetrieveFn retrieve_fn;
} pi_direct_res_rpc_t;

// allocate at runtime?
static pi_direct_res_rpc_t direct_res_rpc[PI_RES_TYPE_MAX];

static cb_mgr_t packet_cb_mgr;
// protects access to registered packet-in CBs
static pthread_mutex_t packet_cb_mutex;

static cb_mgr_t port_cb_mgr;
// protects access to registered port event CBs
static pthread_mutex_t port_cb_mutex;

// acquire device_map_mutex first
pi_device_info_t *pi_get_device_info(pi_dev_id_t dev_id) {
  return (pi_device_info_t *)device_map_get(&device_map, dev_id);
}

void pi_device_lock() { pthread_mutex_lock(&device_map_mutex); }

void pi_device_unlock() { pthread_mutex_unlock(&device_map_mutex); }

// acquire device_map_mutex first
pi_device_info_t *pi_get_devices(size_t *nb) {
  *nb = vector_size(device_arr);
  return (pi_device_info_t *)vector_data(device_arr);
}

const pi_p4info_t *pi_get_device_p4info(pi_dev_id_t dev_id) {
  const pi_p4info_t *p4info = NULL;
  pi_device_lock();
  pi_device_info_t *device_info = pi_get_device_info(dev_id);
  if (device_info != NULL) p4info = device_info->p4info;
  pi_device_unlock();
  return p4info;
}

static size_t direct_res_counter_msg_size(const void *config) {
  (void)config;
  return sizeof(s_pi_counter_data_t);
}

static size_t direct_res_counter_emit(char *dst, const void *config) {
  return emit_counter_data(dst, (const pi_counter_data_t *)config);
}

static size_t direct_res_counter_retrieve(const char *src, void *config) {
  return retrieve_counter_data(src, (pi_counter_data_t *)config);
}

static size_t direct_res_meter_msg_size(const void *config) {
  (void)config;
  return sizeof(s_pi_meter_spec_t);
}

static size_t direct_res_meter_emit(char *dst, const void *config) {
  return emit_meter_spec(dst, (const pi_meter_spec_t *)config);
}

static size_t direct_res_meter_retrieve(const char *src, void *config) {
  return retrieve_meter_spec(src, (pi_meter_spec_t *)config);
}

static void register_std_direct_res() {
  pi_status_t status;
  status =
      pi_direct_res_register(PI_DIRECT_COUNTER_ID, direct_res_counter_msg_size,
                             direct_res_counter_emit, sizeof(pi_counter_data_t),
                             direct_res_counter_retrieve);
  assert(status == PI_STATUS_SUCCESS);
  status = pi_direct_res_register(
      PI_DIRECT_METER_ID, direct_res_meter_msg_size, direct_res_meter_emit,
      sizeof(pi_meter_spec_t), direct_res_meter_retrieve);
  assert(status == PI_STATUS_SUCCESS);
}

pi_status_t pi_init(size_t max_devices, pi_remote_addr_t *remote_addr) {
  (void)max_devices;
  if (device_arr != NULL) return PI_STATUS_INIT_ALREADY_CALLED;
  pi_status_t status;
  // TODO(antonin): best place for this? I don't see another option
  register_std_direct_res();
  if (pthread_mutex_init(&device_map_mutex, NULL))
    return PI_STATUS_PTHREAD_ERROR;
  if (pthread_mutex_init(&packet_cb_mutex, NULL))
    return PI_STATUS_PTHREAD_ERROR;
  if (pthread_mutex_init(&port_cb_mutex, NULL)) return PI_STATUS_PTHREAD_ERROR;
  device_map_create(&device_map);
  device_arr = vector_create(sizeof(pi_device_info_t), 256);
  cb_mgr_init(&packet_cb_mgr);
  cb_mgr_init(&port_cb_mgr);
  status = pi_learn_init();
  if (status != PI_STATUS_SUCCESS) return status;
  status = pi_table_init();
  if (status != PI_STATUS_SUCCESS) return status;

  int abi_version = 0;
  status = _pi_init(&abi_version, (void *)remote_addr);
  if (status != PI_STATUS_SUCCESS) return status;

  if (abi_version != PI_ABI_VERSION) {
    PI_LOG_ERROR(
        "ABI version mismatch between PI core library (%d) and "
        "PI implementation (%d)\n",
        PI_ABI_VERSION, abi_version);
    // assert in DEBUG mode so that the error does not go unnoticed...
    assert(abi_version == PI_ABI_VERSION && "PI ABI version mismatch");
    return PI_STATUS_INVALID_ABI_VERSION;
  }

  return PI_STATUS_SUCCESS;
}

// acquire device_map_mutex first
void pi_update_device_config(pi_dev_id_t dev_id, const pi_p4info_t *p4info) {
  pi_device_info_t *info = pi_get_device_info(dev_id);
  assert(info != NULL);
  info->dev_id = dev_id;
  info->version++;
  info->p4info = p4info;
}

// acquire device_map_mutex first
void pi_create_device_config(pi_dev_id_t dev_id) {
  vector_push_back_empty(device_arr);
  pi_device_info_t *info = (pi_device_info_t *)vector_back(device_arr);
  _PI_ASSERT(device_map_add(&device_map, dev_id, info));
  info->dev_id = dev_id;
}

pi_status_t pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                             pi_assign_extra_t *extra) {
  pi_device_lock();
  if (device_map_exists(&device_map, dev_id)) {
    pi_device_unlock();
    return PI_STATUS_DEV_ALREADY_ASSIGNED;
  }

  _PI_ASSERT(pi_learn_assign_device(dev_id) == PI_STATUS_SUCCESS);
  _PI_ASSERT(pi_table_assign_device(dev_id) == PI_STATUS_SUCCESS);

  pi_status_t status = _pi_assign_device(dev_id, p4info, extra);
  if (status == PI_STATUS_SUCCESS) {
    pi_create_device_config(dev_id);
    pi_update_device_config(dev_id, p4info);
  }
  pi_device_unlock();

  return status;
}

pi_status_t pi_update_device_start(pi_dev_id_t dev_id,
                                   const pi_p4info_t *p4info,
                                   const char *device_data,
                                   size_t device_data_size) {
  pi_status_t status =
      _pi_update_device_start(dev_id, p4info, device_data, device_data_size);
  if (status == PI_STATUS_SUCCESS) {
    pi_device_lock();
    pi_update_device_config(dev_id, p4info);
    pi_device_unlock();
  }

  return status;
}

pi_status_t pi_update_device_end(pi_dev_id_t dev_id) {
  return _pi_update_device_end(dev_id);
}

bool pi_is_device_assigned(pi_dev_id_t dev_id) {
  pi_device_lock();
  bool exists = device_map_exists(&device_map, dev_id);
  pi_device_unlock();
  return exists;
}

size_t pi_num_devices() {
  size_t num_devices = 0;
  pi_device_lock();
  if (device_arr != NULL) num_devices = vector_size(device_arr);
  pi_device_unlock();
  return num_devices;
}

size_t pi_get_device_ids(pi_dev_id_t *dev_ids, size_t max_num_devices) {
  pi_device_lock();
  if (device_arr == NULL) {
    pi_device_unlock();
    return 0;
  }
  size_t num_devices = vector_size(device_arr);
  size_t idx;
  for (idx = 0; idx < num_devices && idx < max_num_devices; idx++) {
    pi_device_info_t *info = (pi_device_info_t *)vector_at(device_arr, idx);
    dev_ids[idx] = info->dev_id;
  }
  pi_device_unlock();
  return idx;
}

pi_status_t pi_remove_device(pi_dev_id_t dev_id) {
  pi_device_lock();
  pi_device_info_t *info = pi_get_device_info(dev_id);
  if (!info) {
    pi_device_unlock();
    return PI_STATUS_DEV_NOT_ASSIGNED;
  }

  pi_status_t status = _pi_remove_device(dev_id);

  vector_remove_e(device_arr, (void *)info);
  _PI_ASSERT(device_map_remove(&device_map, dev_id));

  pthread_mutex_lock(&packet_cb_mutex);
  cb_mgr_rm(&packet_cb_mgr, dev_id);
  pthread_mutex_unlock(&packet_cb_mutex);

  pthread_mutex_lock(&port_cb_mutex);
  cb_mgr_rm(&port_cb_mgr, dev_id);
  pthread_mutex_unlock(&port_cb_mutex);

  _PI_ASSERT(pi_learn_remove_device(dev_id) == PI_STATUS_SUCCESS);
  _PI_ASSERT(pi_table_remove_device(dev_id) == PI_STATUS_SUCCESS);

  pi_device_unlock();

  return status;
}

pi_status_t pi_session_init(pi_session_handle_t *session_handle) {
  return _pi_session_init(session_handle);
}

pi_status_t pi_session_cleanup(pi_session_handle_t session_handle) {
  return _pi_session_cleanup(session_handle);
}

pi_status_t pi_batch_begin(pi_session_handle_t session_handle) {
  return _pi_batch_begin(session_handle);
}

pi_status_t pi_batch_end(pi_session_handle_t session_handle, bool hw_sync) {
  return _pi_batch_end(session_handle, hw_sync);
}

pi_status_t pi_destroy() {
  // This ensures that pi_destroy is idempotent and can be called multiple times
  // without issue and without returning an error. This was added because of
  // some changes to the P4Runtime server C API (which includes functions like
  // PIGrpcServerRunAddr), which may have caused existing client code to call
  // DeviceMgr::destroy (and therefore pi_destroy) more than once.
  if (device_arr == NULL) return PI_STATUS_SUCCESS;
  pi_status_t status;
  pthread_mutex_destroy(&device_map_mutex);
  pthread_mutex_destroy(&packet_cb_mutex);
  pthread_mutex_destroy(&port_cb_mutex);
  vector_destroy(device_arr);
  device_arr = NULL;
  device_map_destroy(&device_map);
  cb_mgr_destroy(&packet_cb_mgr);
  cb_mgr_destroy(&port_cb_mgr);
  status = pi_learn_destroy();
  if (status != PI_STATUS_SUCCESS) return status;
  status = pi_table_destroy();
  if (status != PI_STATUS_SUCCESS) return status;
  return _pi_destroy();
}

bool pi_is_action_id(pi_p4_id_t id) {
  return PI_GET_TYPE_ID(id) == PI_ACTION_ID;
}

bool pi_is_table_id(pi_p4_id_t id) { return PI_GET_TYPE_ID(id) == PI_TABLE_ID; }

bool pi_is_act_prof_id(pi_p4_id_t id) {
  return PI_GET_TYPE_ID(id) == PI_ACT_PROF_ID;
}

bool pi_is_counter_id(pi_p4_id_t id) {
  return PI_GET_TYPE_ID(id) == PI_COUNTER_ID;
}

bool pi_is_direct_counter_id(pi_p4_id_t id) {
  return PI_GET_TYPE_ID(id) == PI_DIRECT_COUNTER_ID;
}

bool pi_is_meter_id(pi_p4_id_t id) { return PI_GET_TYPE_ID(id) == PI_METER_ID; }

bool pi_is_direct_meter_id(pi_p4_id_t id) {
  return PI_GET_TYPE_ID(id) == PI_DIRECT_METER_ID;
}

pi_status_t pi_direct_res_register(pi_res_type_id_t res_type,
                                   PIDirectResMsgSizeFn msg_size_fn,
                                   PIDirectResEmitFn emit_fn, size_t size_of,
                                   PIDirectResRetrieveFn retrieve_fn) {
  if (res_type >= PI_RES_TYPE_MAX) return PI_STATUS_INVALID_RES_TYPE_ID;
  direct_res_rpc[res_type].is_set = 1;
  direct_res_rpc[res_type].msg_size_fn = msg_size_fn;
  direct_res_rpc[res_type].emit_fn = emit_fn;
  direct_res_rpc[res_type].size_of = size_of;
  direct_res_rpc[res_type].retrieve_fn = retrieve_fn;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_direct_res_get_fns(pi_res_type_id_t res_type,
                                  PIDirectResMsgSizeFn *msg_size_fn,
                                  PIDirectResEmitFn *emit_fn, size_t *size_of,
                                  PIDirectResRetrieveFn *retrieve_fn) {
  if (res_type >= PI_RES_TYPE_MAX) return PI_STATUS_INVALID_RES_TYPE_ID;
  if (!direct_res_rpc[res_type].is_set) return PI_STATUS_INVALID_RES_TYPE_ID;
  if (msg_size_fn) *msg_size_fn = direct_res_rpc[res_type].msg_size_fn;
  if (emit_fn) *emit_fn = direct_res_rpc[res_type].emit_fn;
  if (size_of) *size_of = direct_res_rpc[res_type].size_of;
  if (retrieve_fn) *retrieve_fn = direct_res_rpc[res_type].retrieve_fn;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_packetin_register_cb(pi_dev_id_t dev_id, PIPacketInCb cb,
                                    void *cb_cookie) {
  pthread_mutex_lock(&packet_cb_mutex);
  cb_mgr_add(&packet_cb_mgr, dev_id, (GenericFnPtr)cb, cb_cookie);
  pthread_mutex_unlock(&packet_cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_packetin_register_default_cb(PIPacketInCb cb, void *cb_cookie) {
  pthread_mutex_lock(&packet_cb_mutex);
  cb_mgr_set_default(&packet_cb_mgr, (GenericFnPtr)cb, cb_cookie);
  pthread_mutex_unlock(&packet_cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_packetin_deregister_cb(pi_dev_id_t dev_id) {
  pthread_mutex_lock(&packet_cb_mutex);
  cb_mgr_rm(&packet_cb_mgr, dev_id);
  pthread_mutex_unlock(&packet_cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_packetin_deregister_default_cb() {
  pthread_mutex_lock(&packet_cb_mutex);
  cb_mgr_reset_default(&packet_cb_mgr);
  pthread_mutex_unlock(&packet_cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_packetout_send(pi_dev_id_t dev_id, const char *pkt,
                              size_t size) {
  return _pi_packetout_send(dev_id, pkt, size);
}

pi_status_t pi_packetin_receive(pi_dev_id_t dev_id, const char *pkt,
                                size_t size) {
  pthread_mutex_lock(&packet_cb_mutex);
  const cb_data_t *cb_data = cb_mgr_get_or_default(&packet_cb_mgr, dev_id);
  if (cb_data) {
    ((PIPacketInCb)(cb_data->cb))(dev_id, pkt, size, cb_data->cookie);
    pthread_mutex_unlock(&packet_cb_mutex);
    return PI_STATUS_SUCCESS;
  }
  pthread_mutex_unlock(&packet_cb_mutex);
  return PI_STATUS_PACKETIN_NO_CB;
}

pi_status_t pi_port_status_register_cb(pi_dev_id_t dev_id, PIPortStatusCb cb,
                                       void *cb_cookie) {
  pthread_mutex_lock(&port_cb_mutex);
  cb_mgr_add(&port_cb_mgr, dev_id, (GenericFnPtr)cb, cb_cookie);
  pthread_mutex_unlock(&port_cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_port_status_register_default_cb(PIPortStatusCb cb,
                                               void *cb_cookie) {
  pthread_mutex_lock(&port_cb_mutex);
  cb_mgr_set_default(&port_cb_mgr, (GenericFnPtr)cb, cb_cookie);
  pthread_mutex_unlock(&port_cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_port_status_deregister_cb(pi_dev_id_t dev_id) {
  pthread_mutex_lock(&port_cb_mutex);
  cb_mgr_rm(&port_cb_mgr, dev_id);
  pthread_mutex_unlock(&port_cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_port_status_deregister_default_cb() {
  pthread_mutex_lock(&port_cb_mutex);
  cb_mgr_reset_default(&port_cb_mgr);
  pthread_mutex_unlock(&port_cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_port_status_event_notify(pi_dev_id_t dev_id, pi_port_t port,
                                        pi_port_status_t status) {
  pthread_mutex_lock(&port_cb_mutex);
  const cb_data_t *cb_data = cb_mgr_get_or_default(&port_cb_mgr, dev_id);
  if (cb_data) {
    ((PIPortStatusCb)(cb_data->cb))(dev_id, port, status, cb_data->cookie);
    pthread_mutex_unlock(&port_cb_mutex);
    return PI_STATUS_SUCCESS;
  }
  pthread_mutex_unlock(&port_cb_mutex);
  return PI_STATUS_PORT_STATUS_EVENT_NO_CB;
}

pi_status_t pi_port_status_get(pi_dev_id_t dev_id, pi_port_t port,
                               pi_port_status_t *status) {
  return _pi_port_status_get(dev_id, port, status);
}
