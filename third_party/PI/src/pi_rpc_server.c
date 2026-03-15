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

#include "PI/int/pi_int.h"
#include "PI/int/rpc_common.h"
#include "PI/int/serialize.h"
#include "PI/target/pi_act_prof_imp.h"
#include "PI/target/pi_counter_imp.h"
#include "PI/target/pi_imp.h"
#include "PI/target/pi_learn_imp.h"
#include "PI/target/pi_meter_imp.h"
#include "PI/target/pi_tables_imp.h"

#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "_assert.h"
#include "pi_notifications_pub.h"

typedef struct {
  int init;
  pi_rpc_id_t req_id;
  int s;
} pi_rpc_state_t;

static char *rpc_addr = NULL;
static char *notifications_addr = NULL;

static pi_rpc_state_t state;

static void init_addrs(const pi_remote_addr_t *remote_addr) {
  if (!remote_addr || !remote_addr->rpc_addr)
    rpc_addr = strdup("ipc:///tmp/pi_rpc.ipc");
  else
    rpc_addr = strdup(remote_addr->rpc_addr);
  // notifications subscription optional
  if (remote_addr && remote_addr->notifications_addr)
    notifications_addr = strdup(remote_addr->notifications_addr);
}

static size_t emit_rep_hdr(char *hdr, pi_status_t status) {
  size_t s = 0;
  s += emit_rpc_id(hdr, state.req_id);
  s += emit_status(hdr + s, status);
  return s;
}

static void send_status(pi_status_t status) {
  rep_hdr_t rep;
  size_t s = emit_rep_hdr((char *)&rep, status);
  int bytes = nn_send(state.s, &rep, sizeof(rep), 0);
  _PI_UNUSED(s);
  _PI_UNUSED(bytes);
  assert((size_t)bytes == s);
}

// all of this is a little complicated, maybe multiple calls to malloc would be
// just as efficient...

#define ALIGN 16
#define ALIGN_SIZE(s) (((s) + (ALIGN - 1)) & (~(ALIGN - 1)))

static pi_direct_res_config_t *allocate_direct_res_config(const char *src) {
  uint32_t num_configs;
  size_t s = retrieve_uint32(src, &num_configs);
  if (num_configs == 0) return NULL;
  size_t required_size = sizeof(pi_direct_res_config_t);
  required_size = ALIGN_SIZE(required_size);
  size_t header_stop = required_size;
  required_size += num_configs * sizeof(pi_direct_res_config_one_t);
  required_size = ALIGN_SIZE(required_size);
  size_t config_start = required_size;
  for (size_t i = 0; i < num_configs; i++) {
    pi_p4_id_t res_id;
    s += retrieve_p4_id(src + s, &res_id);
    pi_res_type_id_t type = PI_GET_TYPE_ID(res_id);
    uint32_t msg_size;
    s += retrieve_uint32(src + s, &msg_size);
    src += msg_size;
    size_t size_of;
    pi_direct_res_get_fns(type, NULL, NULL, &size_of, NULL);
    required_size += size_of;
    required_size = ALIGN_SIZE(required_size);
  }
  char *data = malloc(required_size);
  pi_direct_res_config_t *direct_config = (pi_direct_res_config_t *)data;
  direct_config->num_configs = num_configs;
  direct_config->configs = (pi_direct_res_config_one_t *)(data + header_stop);
  // num_configs is at least 1
  // this is a hack to store where configs can be written to (for retrieve fn)
  direct_config->configs[0].config = data + config_start;
  return direct_config;
}

static size_t retrieve_direct_res_config(
    const char *src, pi_direct_res_config_t *direct_config) {
  size_t s = sizeof(uint32_t);  // skip num configs
  if (!direct_config) return s;
  size_t num_configs = direct_config->num_configs;
  char *curr = (char *)direct_config->configs[0].config;
  for (size_t i = 0; i < num_configs; i++) {
    pi_direct_res_config_one_t *config = &direct_config->configs[i];
    s += retrieve_p4_id(src + s, &config->res_id);
    s += sizeof(uint32_t);  // skip size
    pi_res_type_id_t type = PI_GET_TYPE_ID(config->res_id);
    PIDirectResRetrieveFn retrieve_fn;
    size_t size_of;
    pi_direct_res_get_fns(type, NULL, NULL, &size_of, &retrieve_fn);
    config->config = curr;
    curr += ALIGN_SIZE(size_of);
    s += retrieve_fn(src + s, config->config);
  }
  return s;
}

static void free_direct_res_config(pi_direct_res_config_t *direct_config) {
  if (direct_config) free(direct_config);
}

static void __pi_init(char *req) {
  printf("RPC: _pi_init\n");

  (void)req;
  pi_device_lock();
  size_t num_devices;
  pi_device_info_t *devices = pi_get_devices(&num_devices);
  pi_status_t status = PI_STATUS_SUCCESS;
  if (!devices) {  // not init yet
    assert(num_devices == 0);
    int abi_version;
    status = _pi_init(NULL, &abi_version);
    assert(abi_version == PI_ABI_VERSION);
  }

  typedef struct {
    char *json;
    size_t size;
  } p4info_tmp_t;
  p4info_tmp_t *p4info_tmp = NULL;

  size_t s = sizeof(rep_hdr_t);
  s += sizeof(uint32_t);  // num devices

  if (num_devices > 0) {
    p4info_tmp = calloc(num_devices, sizeof(*p4info_tmp));
  }

  for (size_t idx = 0; idx < num_devices; idx++) {
    s += sizeof(s_pi_dev_id_t);
    s += sizeof(uint32_t);  // version
    p4info_tmp[idx].json = pi_serialize_config(devices[idx].p4info, 0);
    p4info_tmp[idx].size = strlen(p4info_tmp[idx].json) + 1;
    s += p4info_tmp[idx].size;
  }

  char *rep = nn_allocmsg(s, 0);
  char *rep_ = rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_uint32(rep_, num_devices);
  for (size_t idx = 0; idx < num_devices; idx++) {
    rep_ += emit_dev_id(rep_, devices[idx].dev_id);
    rep_ += emit_uint32(rep_, devices[idx].version);
    memcpy(rep_, p4info_tmp[idx].json, p4info_tmp[idx].size);
    rep_ += p4info_tmp[idx].size;
  }

  if (num_devices > 0) {
    assert(p4info_tmp);
    free(p4info_tmp);
  }

  assert((size_t)(rep_ - rep) == s);

  int bytes = nn_send(state.s, &rep, NN_MSG, 0);
  _PI_UNUSED(bytes);
  assert((size_t)bytes == s);
  pi_device_unlock();
}

static void __pi_assign_device(char *req) {
  printf("RPC: _pi_assign_device\n");

  pi_status_t status;
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);

  if (pi_is_device_assigned(dev_id)) {
    send_status(PI_STATUS_DEV_ALREADY_ASSIGNED);
    return;
  }

  size_t p4info_size = strlen(req) + 1;
  pi_p4info_t *p4info = NULL;
  if (p4info_size > 1) {
    // TODO(antonin): when is this destroyed?
    status = pi_add_config(req, PI_CONFIG_TYPE_NATIVE_JSON, &p4info);
    if (status != PI_STATUS_SUCCESS) {
      send_status(status);
      return;
    }
  }
  req += p4info_size;

  // extras
  uint32_t num_extras;
  req += retrieve_uint32(req, &num_extras);

  size_t extras_size = sizeof(pi_assign_extra_t) * (num_extras + 1);
  pi_assign_extra_t *extras = malloc(extras_size);
  memset(extras, 0, extras_size);
  for (size_t i = 0; i < num_extras; i++) {
    extras[i].key = req;
    req = strchr(req, '\0') + 1;
    extras[i].v = req;
    req = strchr(req, '\0') + 1;
  }
  extras[num_extras].end_of_extras = 1;

  status = pi_assign_device(dev_id, p4info, extras);
  free(extras);

  send_status(status);
}

static void __pi_update_device_start(char *req) {
  printf("RPC: _pi_update_device_start\n");

  pi_status_t status;
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);

  if (!pi_is_device_assigned(dev_id)) {
    send_status(PI_STATUS_DEV_NOT_ASSIGNED);
    return;
  }

  size_t p4info_size = strlen(req) + 1;
  pi_p4info_t *p4info;
  // TODO(antonin): when is this destroyed?
  status = pi_add_config(req, PI_CONFIG_TYPE_NATIVE_JSON, &p4info);
  if (status != PI_STATUS_SUCCESS) {
    send_status(status);
    return;
  }
  req += p4info_size;

  uint32_t device_data_size;
  req += retrieve_uint32(req, &device_data_size);

  status = _pi_update_device_start(dev_id, p4info, req, device_data_size);

  if (status == PI_STATUS_SUCCESS) pi_update_device_config(dev_id, p4info);

  send_status(status);
}

static void __pi_update_device_end(char *req) {
  printf("RPC: _pi_update_device_end\n");

  pi_dev_id_t dev_id;
  retrieve_dev_id(req, &dev_id);

  pi_status_t status = _pi_update_device_end(dev_id);

  send_status(status);
}

static void __pi_remove_device(char *req) {
  printf("RPC: _pi_remove_device\n");

  pi_dev_id_t dev_id;
  retrieve_dev_id(req, &dev_id);

  if (!pi_is_device_assigned(dev_id)) {
    send_status(PI_STATUS_DEV_NOT_ASSIGNED);
    return;
  }

  pi_status_t status = pi_remove_device(dev_id);
  send_status(status);
}

static void __pi_destroy(char *req) {
  printf("RPC: _pi_destroy\n");

  (void)req;
  send_status(_pi_destroy());
}

static void __pi_session_init(char *req) {
  printf("RPC: _pi_session_init\n");

  (void)req;

  pi_session_handle_t sess = 0;
  pi_status_t status = _pi_session_init(&sess);

  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_session_handle_t h;
  } rep_t;
  rep_t rep;
  char *rep_ = (char *)&rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_session_handle(rep_, sess);

  int bytes = nn_send(state.s, &rep, sizeof(rep), 0);
  _PI_UNUSED(bytes);
  assert(bytes == sizeof(rep));
}

static void __pi_session_cleanup(char *req) {
  printf("RPC: _pi_session_cleanup\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);

  send_status(_pi_session_cleanup(sess));
}

static void __pi_batch_begin(char *req) {
  printf("RPC: _pi_batch_begin\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);

  send_status(_pi_batch_begin(sess));
}

static void __pi_batch_end(char *req) {
  printf("RPC: _pi_batch_end\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  uint32_t hw_sync;
  req += retrieve_uint32(req, &hw_sync);

  send_status(_pi_batch_end(sess, (bool)hw_sync));
}

// src cannot const because we are not copying key data, instead we are pointing
// directly inside the message buffer
static size_t retrieve_match_key(char *src, pi_match_key_t *match_key) {
  size_t s = 0;
  // p4info and table_id must be filled by callee
  s += retrieve_uint32(src + s, &match_key->priority);
  uint32_t mk_size;
  s += retrieve_uint32(src + s, &mk_size);
  match_key->data_size = mk_size;
  match_key->data = src + s;
  s += mk_size;
  return s;
}

static void __pi_table_entry_add(char *req) {
  printf("RPC: _pi_table_entry_add\n");

  // TODO(antonin): find a way to take care of p4info for mk and ad
  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);

  pi_match_key_t match_key;
  match_key.p4info = NULL;  // TODO(antonin)
  match_key.table_id = table_id;
  req += retrieve_match_key(req, &match_key);

  pi_table_entry_t table_entry;
  // in case the entry is action data, we allocate a struct on the stack
  pi_action_data_t action_data;
  table_entry.entry.action_data = &action_data;
  req += retrieve_table_entry(req, &table_entry, 0);
  pi_direct_res_config_t *direct_config = allocate_direct_res_config(req);
  req += retrieve_direct_res_config(req, direct_config);
  table_entry.direct_res_config = direct_config;

  uint32_t overwrite;
  req += retrieve_uint32(req, &overwrite);

  pi_entry_handle_t entry_handle;
  pi_status_t status =
      _pi_table_entry_add(sess, dev_tgt, table_id, &match_key, &table_entry,
                          overwrite, &entry_handle);

  free_direct_res_config(direct_config);

  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_entry_handle_t h;
  } rep_t;
  rep_t rep;
  char *rep_ = (char *)&rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_entry_handle(rep_, entry_handle);

  int bytes = nn_send(state.s, &rep, sizeof(rep), 0);
  _PI_UNUSED(bytes);
  assert(bytes == sizeof(rep));
}

static void __pi_table_default_action_set(char *req) {
  printf("RPC: _pi_table_default_action_set\n");

  // TODO(antonin): find a way to take care of p4info for ad
  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);

  pi_table_entry_t table_entry;
  pi_action_data_t action_data;
  table_entry.entry.action_data = &action_data;
  req += retrieve_table_entry(req, &table_entry, 0);
  pi_direct_res_config_t *direct_config = allocate_direct_res_config(req);
  req += retrieve_direct_res_config(req, direct_config);
  table_entry.direct_res_config = direct_config;

  pi_status_t status =
      _pi_table_default_action_set(sess, dev_tgt, table_id, &table_entry);

  free_direct_res_config(direct_config);

  send_status(status);
}

static void __pi_table_default_action_reset(char *req) {
  printf("RPC: _pi_table_default_action_reset\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);

  pi_status_t status = _pi_table_default_action_reset(sess, dev_tgt, table_id);

  send_status(status);
}

static void __pi_table_default_action_get(char *req) {
  printf("RPC: _pi_table_default_action_get\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);

  pi_table_entry_t default_entry;
  // not supported yet for entry retrieval
  default_entry.direct_res_config = NULL;
  pi_status_t status =
      _pi_table_default_action_get(sess, dev_tgt, table_id, &default_entry);

  size_t s = 0;
  s += sizeof(rep_hdr_t);
  s += table_entry_size(&default_entry);

  char *rep = nn_allocmsg(s, 0);
  char *rep_ = rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_table_entry(rep_, &default_entry);

  // release target memory
  _pi_table_default_action_done(sess, &default_entry);

  // make sure I have copied exactly the right amount
  assert((size_t)(rep_ - rep) == s);

  int bytes = nn_send(state.s, &rep, NN_MSG, 0);
  _PI_UNUSED(bytes);
  assert((size_t)bytes == s);
}

static void __pi_table_entry_delete(char *req) {
  printf("RPC: _pi_table_entry_delete\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);
  pi_entry_handle_t h;
  req += retrieve_entry_handle(req, &h);

  send_status(_pi_table_entry_delete(sess, dev_id, table_id, h));
}

static void __pi_table_entry_delete_wkey(char *req) {
  printf("RPC: _pi_table_entry_delete_wkey\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);
  pi_match_key_t match_key;
  match_key.p4info = NULL;  // TODO(antonin)
  match_key.table_id = table_id;
  req += retrieve_match_key(req, &match_key);

  send_status(_pi_table_entry_delete_wkey(sess, dev_tgt, table_id, &match_key));
}

static void __pi_table_entry_modify_common(char *req, bool wkey) {
  // TODO(antonin): find a way to take care of p4info for mk and ad
  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_id_t dev_id;
  pi_dev_tgt_t dev_tgt;
  if (wkey) {
    req += retrieve_dev_tgt(req, &dev_tgt);
  } else {
    req += retrieve_dev_id(req, &dev_id);
  }
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);

  pi_entry_handle_t h;
  pi_match_key_t match_key;
  if (wkey) {
    match_key.p4info = NULL;  // TODO(antonin)
    match_key.table_id = table_id;
    req += retrieve_match_key(req, &match_key);
  } else {
    req += retrieve_entry_handle(req, &h);
  }

  pi_table_entry_t table_entry;
  pi_action_data_t action_data;
  table_entry.entry.action_data = &action_data;
  req += retrieve_table_entry(req, &table_entry, 0);
  pi_direct_res_config_t *direct_config = allocate_direct_res_config(req);
  req += retrieve_direct_res_config(req, direct_config);
  table_entry.direct_res_config = direct_config;

  pi_status_t status;

  if (wkey) {
    status = _pi_table_entry_modify_wkey(sess, dev_tgt, table_id, &match_key,
                                         &table_entry);
  } else {
    status = _pi_table_entry_modify(sess, dev_id, table_id, h, &table_entry);
  }

  free_direct_res_config(direct_config);

  send_status(status);
}

static void __pi_table_entry_modify(char *req) {
  printf("RPC: _pi_table_entry_modify\n");
  __pi_table_entry_modify_common(req, false);
}

static void __pi_table_entry_modify_wkey(char *req) {
  printf("RPC: _pi_table_entry_modify_wkey\n");
  __pi_table_entry_modify_common(req, true);
}

static void __pi_table_entries_fetch(char *req) {
  printf("RPC: _pi_table_entries_fetch\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);

  pi_table_fetch_res_t res;
  pi_status_t status = _pi_table_entries_fetch(sess, dev_tgt, table_id, &res);

  if (status != PI_STATUS_SUCCESS) {
    send_status(status);
    return;
  }

  size_t s = 0;
  s += sizeof(rep_hdr_t);
  s += sizeof(uint32_t);  // num entries
  s += sizeof(uint32_t);  // mkey nbytes
  s += sizeof(uint32_t);  // entries_size (in bytes)
  s += res.entries_size;

  char *rep = nn_allocmsg(s, 0);
  char *rep_ = rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_uint32(rep_, res.num_entries);
  rep_ += emit_uint32(rep_, res.mkey_nbytes);
  rep_ += emit_uint32(rep_, res.entries_size);
  memcpy(rep_, res.entries, res.entries_size);
  rep_ += res.entries_size;

  // release target memory
  _pi_table_entries_fetch_done(sess, &res);

  // make sure I have copied exactly the right amount
  assert((size_t)(rep_ - rep) == s);

  int bytes = nn_send(state.s, &rep, NN_MSG, 0);
  _PI_UNUSED(bytes);
  assert((size_t)bytes == s);
}

static void send_indirect_handle(pi_status_t status, pi_indirect_handle_t h) {
  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_indirect_handle_t h;
  } rep_t;
  rep_t rep;
  char *rep_ = (char *)&rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_indirect_handle(rep_, h);

  int bytes = nn_send(state.s, &rep, sizeof(rep), 0);
  _PI_UNUSED(bytes);
  assert(bytes == sizeof(rep));
}

static void __pi_act_prof_mbr_create(char *req) {
  printf("RPC: _pi_act_prof_mbr_create\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t act_prof_id;
  req += retrieve_p4_id(req, &act_prof_id);

  pi_action_data_t action_data;
  pi_action_data_t *action_data_ = &action_data;
  action_data.p4info = NULL;  // TODO(antonin)
  req += retrieve_action_data(req, &action_data_, 0);

  pi_indirect_handle_t mbr_handle = 0;
  pi_status_t status = _pi_act_prof_mbr_create(sess, dev_tgt, act_prof_id,
                                               &action_data, &mbr_handle);
  send_indirect_handle(status, mbr_handle);
}

static void __pi_act_prof_mbr_delete(char *req) {
  printf("RPC: _pi_act_prof_mbr_delete\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);
  pi_p4_id_t act_prof_id;
  req += retrieve_p4_id(req, &act_prof_id);
  pi_indirect_handle_t mbr_handle;
  req += retrieve_indirect_handle(req, &mbr_handle);

  pi_status_t status =
      _pi_act_prof_mbr_delete(sess, dev_id, act_prof_id, mbr_handle);
  send_status(status);
}

static void __pi_act_prof_mbr_modify(char *req) {
  printf("RPC: _pi_act_prof_mbr_modify\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);
  pi_p4_id_t act_prof_id;
  req += retrieve_p4_id(req, &act_prof_id);
  pi_indirect_handle_t mbr_handle;
  req += retrieve_indirect_handle(req, &mbr_handle);

  pi_action_data_t action_data;
  pi_action_data_t *action_data_ = &action_data;
  action_data.p4info = NULL;  // TODO(antonin)
  req += retrieve_action_data(req, &action_data_, 0);

  pi_status_t status = _pi_act_prof_mbr_modify(sess, dev_id, act_prof_id,
                                               mbr_handle, &action_data);
  send_status(status);
}

static void __pi_act_prof_grp_create(char *req) {
  printf("RPC: _pi_act_prof_grp_create\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t act_prof_id;
  req += retrieve_p4_id(req, &act_prof_id);
  uint32_t max_size;
  req += retrieve_uint32(req, &max_size);

  pi_indirect_handle_t grp_handle = 0;
  pi_status_t status = _pi_act_prof_grp_create(sess, dev_tgt, act_prof_id,
                                               max_size, &grp_handle);
  send_indirect_handle(status, grp_handle);
}

static void __pi_act_prof_grp_delete(char *req) {
  printf("RPC: _pi_act_prof_grp_delete\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);
  pi_p4_id_t act_prof_id;
  req += retrieve_p4_id(req, &act_prof_id);
  pi_indirect_handle_t grp_handle;
  req += retrieve_indirect_handle(req, &grp_handle);

  pi_status_t status =
      _pi_act_prof_grp_delete(sess, dev_id, act_prof_id, grp_handle);
  send_status(status);
}

static void grp_add_remove_mbr(char *req, pi_rpc_type_t add_or_remove) {
  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);
  pi_p4_id_t act_prof_id;
  req += retrieve_p4_id(req, &act_prof_id);
  pi_indirect_handle_t grp_handle;
  req += retrieve_indirect_handle(req, &grp_handle);
  pi_indirect_handle_t mbr_handle;
  req += retrieve_indirect_handle(req, &mbr_handle);

  pi_status_t status;
  switch (add_or_remove) {
    case PI_RPC_ACT_PROF_GRP_ADD_MBR:
      status = _pi_act_prof_grp_add_mbr(sess, dev_id, act_prof_id, grp_handle,
                                        mbr_handle);
      break;
    case PI_RPC_ACT_PROF_GRP_REMOVE_MBR:
      status = _pi_act_prof_grp_remove_mbr(sess, dev_id, act_prof_id,
                                           grp_handle, mbr_handle);
      break;
    default:
      _PI_UNREACHABLE("Invalid switch case");
  }

  send_status(status);
}

static void __pi_act_prof_grp_add_mbr(char *req) {
  printf("RPC: _pi_act_prof_grp_add_mbr\n");
  grp_add_remove_mbr(req, PI_RPC_ACT_PROF_GRP_ADD_MBR);
}

static void __pi_act_prof_grp_remove_mbr(char *req) {
  printf("RPC: _pi_act_prof_grp_remove_mbr\n");
  grp_add_remove_mbr(req, PI_RPC_ACT_PROF_GRP_REMOVE_MBR);
}

static void __pi_act_prof_entries_fetch(char *req) {
  printf("RPC: _pi_act_prof_entries_fetch\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t act_prof_id;
  req += retrieve_p4_id(req, &act_prof_id);

  pi_act_prof_fetch_res_t res;
  pi_status_t status =
      _pi_act_prof_entries_fetch(sess, dev_tgt, act_prof_id, &res);

  if (status != PI_STATUS_SUCCESS) {
    send_status(status);
    return;
  }

  size_t s = 0;
  s += sizeof(rep_hdr_t);
  s += sizeof(uint32_t);  // num members
  s += sizeof(uint32_t);  // num groups
  s += sizeof(uint32_t);  // members size (in bytes)
  s += res.entries_members_size;
  s += sizeof(uint32_t);  // groups size (in bytes)
  s += res.entries_groups_size;
  s += sizeof(uint32_t);  // num mbr handles
  size_t mbr_handles_size =
      res.num_cumulated_mbr_handles * sizeof(s_pi_indirect_handle_t);
  s += mbr_handles_size;

  char *rep = nn_allocmsg(s, 0);
  char *rep_ = rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_uint32(rep_, res.num_members);
  rep_ += emit_uint32(rep_, res.num_groups);
  rep_ += emit_uint32(rep_, res.entries_members_size);
  memcpy(rep_, res.entries_members, res.entries_members_size);
  rep_ += res.entries_members_size;
  rep_ += emit_uint32(rep_, res.entries_groups_size);
  memcpy(rep_, res.entries_groups, res.entries_groups_size);
  rep_ += res.entries_groups_size;
  rep_ += emit_uint32(rep_, res.num_cumulated_mbr_handles);
  assert(sizeof(pi_indirect_handle_t) == sizeof(s_pi_indirect_handle_t));
  memcpy(rep_, res.mbr_handles, mbr_handles_size);
  rep_ += mbr_handles_size;

  // release target memory
  _pi_act_prof_entries_fetch_done(sess, &res);

  // make sure I have copied exactly the right amount
  assert((size_t)(rep_ - rep) == s);

  int bytes = nn_send(state.s, &rep, NN_MSG, 0);
  _PI_UNUSED(bytes);
  assert((size_t)bytes == s);
}

static void counter_read(char *req, pi_rpc_type_t direct_or_not) {
  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t counter_id;
  req += retrieve_p4_id(req, &counter_id);
  uint64_t h;
  req += retrieve_uint64(req, &h);
  uint32_t flags;
  req += retrieve_uint32(req, &flags);

  pi_counter_data_t counter_data;
  pi_status_t status;
  switch (direct_or_not) {
    case PI_RPC_COUNTER_READ:
      status =
          _pi_counter_read(sess, dev_tgt, counter_id, h, flags, &counter_data);
      break;
    case PI_RPC_COUNTER_READ_DIRECT:
      status = _pi_counter_read_direct(sess, dev_tgt, counter_id, h, flags,
                                       &counter_data);
      break;
    default:
      _PI_UNREACHABLE("Invalid switch case");
      assert(0);
  }

  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_counter_data_t counter_data;
  } rep_t;
  rep_t rep;
  char *rep_ = (char *)&rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_counter_data(rep_, &counter_data);

  int bytes = nn_send(state.s, &rep, sizeof(rep), 0);
  _PI_UNUSED(bytes);
  assert(bytes == sizeof(rep));
}

static void __pi_counter_read(char *req) {
  printf("RPC: _pi_counter_read\n");
  counter_read(req, PI_RPC_COUNTER_READ);
}

static void __pi_counter_read_direct(char *req) {
  printf("RPC: _pi_counter_read_direct\n");
  counter_read(req, PI_RPC_COUNTER_READ_DIRECT);
}

static void counter_write(char *req, pi_rpc_type_t direct_or_not) {
  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t counter_id;
  req += retrieve_p4_id(req, &counter_id);
  uint64_t h;
  req += retrieve_uint64(req, &h);
  pi_counter_data_t counter_data;
  req += retrieve_counter_data(req, &counter_data);

  pi_status_t status;
  switch (direct_or_not) {
    case PI_RPC_COUNTER_WRITE:
      status = _pi_counter_write(sess, dev_tgt, counter_id, h, &counter_data);
      break;
    case PI_RPC_COUNTER_WRITE_DIRECT:
      status =
          _pi_counter_write_direct(sess, dev_tgt, counter_id, h, &counter_data);
      break;
    default:
      _PI_UNREACHABLE("Invalid switch case");
  }

  send_status(status);
}

static void __pi_counter_write(char *req) {
  printf("RPC: _pi_counter_write\n");
  counter_write(req, PI_RPC_COUNTER_WRITE);
}

static void __pi_counter_write_direct(char *req) {
  printf("RPC: _pi_counter_write_direct\n");
  counter_write(req, PI_RPC_COUNTER_WRITE_DIRECT);
}

static void meter_read(char *req, pi_rpc_type_t direct_or_not) {
  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t meter_id;
  req += retrieve_p4_id(req, &meter_id);
  uint64_t h;
  req += retrieve_uint64(req, &h);

  pi_meter_spec_t meter_spec;
  pi_status_t status;
  switch (direct_or_not) {
    case PI_RPC_METER_READ:
      status = _pi_meter_read(sess, dev_tgt, meter_id, h, &meter_spec);
      break;
    case PI_RPC_METER_READ_DIRECT:
      status = _pi_meter_read_direct(sess, dev_tgt, meter_id, h, &meter_spec);
      break;
    default:
      _PI_UNREACHABLE("Invalid switch case");
  }

  // e.g. if meter spec was not set previously
  if (status != PI_STATUS_SUCCESS) memset(&meter_spec, 0, sizeof(meter_spec));

  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_meter_spec_t meter_spec;
  } rep_t;
  rep_t rep;
  char *rep_ = (char *)&rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_meter_spec(rep_, &meter_spec);

  int bytes = nn_send(state.s, &rep, sizeof(rep), 0);
  _PI_UNUSED(bytes);
  assert(bytes == sizeof(rep));
}

static void __pi_meter_read(char *req) {
  printf("RPC: _pi_meter_read\n");
  meter_read(req, PI_RPC_METER_READ);
}

static void __pi_meter_read_direct(char *req) {
  printf("RPC: _pi_meter_read_direct\n");
  meter_read(req, PI_RPC_METER_READ_DIRECT);
}

static void meter_set(char *req, pi_rpc_type_t direct_or_not) {
  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t meter_id;
  req += retrieve_p4_id(req, &meter_id);
  uint64_t h;
  req += retrieve_uint64(req, &h);
  pi_meter_spec_t meter_spec;
  req += retrieve_meter_spec(req, &meter_spec);

  pi_status_t status;
  switch (direct_or_not) {
    case PI_RPC_METER_SET:
      status = _pi_meter_set(sess, dev_tgt, meter_id, h, &meter_spec);
      break;
    case PI_RPC_METER_SET_DIRECT:
      status = _pi_meter_set_direct(sess, dev_tgt, meter_id, h, &meter_spec);
      break;
    default:
      _PI_UNREACHABLE("Invalid switch case");
  }

  send_status(status);
}

static void __pi_meter_set(char *req) {
  printf("RPC: _pi_meter_set\n");
  meter_set(req, PI_RPC_METER_SET);
}

static void __pi_meter_set_direct(char *req) {
  printf("RPC: _pi_meter_set_direct\n");
  meter_set(req, PI_RPC_METER_SET_DIRECT);
}

static void __pi_learn_msg_ack(char *req) {
  printf("RPC: _pi_learn_msg_ack\n");
  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);
  pi_p4_id_t learn_id;
  req += retrieve_p4_id(req, &learn_id);
  pi_learn_msg_id_t msg_id;
  req += retrieve_learn_msg_id(req, &msg_id);

  pi_status_t status = _pi_learn_msg_ack(sess, dev_id, learn_id, msg_id);
  send_status(status);
}

static void __pi_packetout_send(char *req) {
  printf("RPC: _pi_packetout_send\n");
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);
  uint32_t msg_size;
  req += retrieve_uint32(req, &msg_size);

  pi_status_t status = _pi_packetout_send(dev_id, req, msg_size);
  send_status(status);
}

static void learn_cb(pi_learn_msg_t *msg, void *cb_cookie) {
  (void)cb_cookie;
  pi_notifications_pub_learn(msg);
  _pi_learn_msg_done(msg);
}

static void packetin_cb(pi_dev_id_t dev_id, const char *pkt, size_t size,
                        void *cb_cookie) {
  (void)cb_cookie;
  pi_notifications_pub_packetin(dev_id, pkt, size);
}

pi_status_t pi_rpc_server_run(const pi_remote_addr_t *remote_addr) {
  assert(!state.init);
  init_addrs(remote_addr);
  state.s = nn_socket(AF_SP, NN_REP);
  if (state.s < 0) return PI_STATUS_RPC_CONNECT_ERROR;
  if (nn_bind(state.s, rpc_addr) < 0) return PI_STATUS_RPC_CONNECT_ERROR;

  if (notifications_addr) {
    pi_status_t status = pi_notifications_init(notifications_addr);
    if (status != PI_STATUS_SUCCESS) return status;
    _PI_ASSERT(pi_learn_register_default_cb(learn_cb, NULL) ==
               PI_STATUS_SUCCESS);
    _PI_ASSERT(pi_packetin_register_default_cb(packetin_cb, NULL) ==
               PI_STATUS_SUCCESS);
  }

  state.init = 1;

  while (1) {
    char *req = NULL;
    int bytes = nn_recv(state.s, &req, NN_MSG, 0);
    if (bytes < 0) return PI_STATUS_RPC_TRANSPORT_ERROR;
    if (bytes == 0) continue;

    pi_rpc_type_t type;
    char *req_ = req;
    req_ += retrieve_rpc_id(req_, &state.req_id);
    printf("req_id: %u\n", state.req_id);
    req_ += retrieve_rpc_type(req_, &type);

    switch (type) {
      case PI_RPC_INIT:
        __pi_init(req_);
        break;
      case PI_RPC_ASSIGN_DEVICE:
        __pi_assign_device(req_);
        break;
      case PI_RPC_UPDATE_DEVICE_START:
        __pi_update_device_start(req_);
        break;
      case PI_RPC_UPDATE_DEVICE_END:
        __pi_update_device_end(req_);
        break;
      case PI_RPC_REMOVE_DEVICE:
        __pi_remove_device(req_);
        break;
      case PI_RPC_DESTROY:
        __pi_destroy(req_);
        break;
      case PI_RPC_SESSION_INIT:
        __pi_session_init(req_);
        break;
      case PI_RPC_SESSION_CLEANUP:
        __pi_session_cleanup(req_);
        break;
      case PI_RPC_BATCH_BEGIN:
        __pi_batch_begin(req_);
        break;
      case PI_RPC_BATCH_END:
        __pi_batch_end(req_);
        break;
      case PI_RPC_TABLE_ENTRY_ADD:
        __pi_table_entry_add(req_);
        break;
      case PI_RPC_TABLE_DEFAULT_ACTION_SET:
        __pi_table_default_action_set(req_);
        break;
      case PI_RPC_TABLE_DEFAULT_ACTION_RESET:
        __pi_table_default_action_reset(req_);
        break;
      case PI_RPC_TABLE_DEFAULT_ACTION_GET:
        __pi_table_default_action_get(req_);
        break;
      case PI_RPC_TABLE_ENTRY_DELETE:
        __pi_table_entry_delete(req_);
        break;
      case PI_RPC_TABLE_ENTRY_DELETE_WKEY:
        __pi_table_entry_delete_wkey(req_);
        break;
      case PI_RPC_TABLE_ENTRY_MODIFY:
        __pi_table_entry_modify(req_);
        break;
      case PI_RPC_TABLE_ENTRY_MODIFY_WKEY:
        __pi_table_entry_modify_wkey(req_);
        break;
      case PI_RPC_TABLE_ENTRIES_FETCH:
        __pi_table_entries_fetch(req_);
        break;

      case PI_RPC_ACT_PROF_MBR_CREATE:
        __pi_act_prof_mbr_create(req_);
        break;
      case PI_RPC_ACT_PROF_MBR_DELETE:
        __pi_act_prof_mbr_delete(req_);
        break;
      case PI_RPC_ACT_PROF_MBR_MODIFY:
        __pi_act_prof_mbr_modify(req_);
        break;
      case PI_RPC_ACT_PROF_GRP_CREATE:
        __pi_act_prof_grp_create(req_);
        break;
      case PI_RPC_ACT_PROF_GRP_DELETE:
        __pi_act_prof_grp_delete(req_);
        break;
      case PI_RPC_ACT_PROF_GRP_ADD_MBR:
        __pi_act_prof_grp_add_mbr(req_);
        break;
      case PI_RPC_ACT_PROF_GRP_REMOVE_MBR:
        __pi_act_prof_grp_remove_mbr(req_);
        break;
      case PI_RPC_ACT_PROF_ENTRIES_FETCH:
        __pi_act_prof_entries_fetch(req_);
        break;

      case PI_RPC_COUNTER_READ:
        __pi_counter_read(req_);
        break;
      case PI_RPC_COUNTER_READ_DIRECT:
        __pi_counter_read_direct(req_);
        break;
      case PI_RPC_COUNTER_WRITE:
        __pi_counter_write(req_);
        break;
      case PI_RPC_COUNTER_WRITE_DIRECT:
        __pi_counter_write_direct(req_);
        break;

      case PI_RPC_METER_READ:
        __pi_meter_read(req_);
        break;
      case PI_RPC_METER_READ_DIRECT:
        __pi_meter_read_direct(req_);
        break;
      case PI_RPC_METER_SET:
        __pi_meter_set(req_);
        break;
      case PI_RPC_METER_SET_DIRECT:
        __pi_meter_set_direct(req_);
        break;

      case PI_RPC_LEARN_MSG_ACK:
        __pi_learn_msg_ack(req_);
        break;

      case PI_RPC_PACKETOUT_SEND:
        __pi_packetout_send(req_);
        break;

      default:
        assert(0);
    }

    nn_freemsg(req);
  }

  return PI_STATUS_SUCCESS;
}

// some helper functions declared in rpc_common.h

size_t emit_rpc_id(char *dst, pi_rpc_id_t v) { return emit_uint32(dst, v); }

size_t retrieve_rpc_id(const char *src, pi_rpc_id_t *v) {
  return retrieve_uint32(src, v);
}

size_t emit_rpc_type(char *dst, pi_rpc_type_t v) { return emit_uint32(dst, v); }

size_t retrieve_rpc_type(const char *src, pi_rpc_type_t *v) {
  return retrieve_uint32(src, v);
}

size_t action_data_size(const pi_action_data_t *action_data) {
  size_t s = 0;
  s += sizeof(s_pi_p4_id_t);  // action_id
  s += sizeof(uint32_t);      // action data size
  s += action_data->data_size;
  return s;
}

size_t table_entry_size(const pi_table_entry_t *table_entry) {
  size_t s = 0;
  s += sizeof(s_pi_action_entry_type_t);
  switch (table_entry->entry_type) {
    case PI_ACTION_ENTRY_TYPE_NONE:
      break;
    case PI_ACTION_ENTRY_TYPE_DATA:
      s += action_data_size(table_entry->entry.action_data);
      break;
    case PI_ACTION_ENTRY_TYPE_INDIRECT:
      s += sizeof(s_pi_indirect_handle_t);
      break;
    default:
      assert(0);
  }
  s += direct_res_config_size(table_entry->direct_res_config);
  // TODO(antonin): properties
  return s;
}

size_t emit_action_data(char *dst, const pi_action_data_t *action_data) {
  size_t s = 0;
  s += emit_p4_id(dst, action_data->action_id);
  s += emit_uint32(dst + s, action_data->data_size);
  if (action_data->data_size > 0) {
    memcpy(dst + s, action_data->data, action_data->data_size);
    s += action_data->data_size;
  }
  return s;
}

size_t emit_table_entry(char *dst, const pi_table_entry_t *table_entry) {
  size_t s = 0;
  s += emit_action_entry_type(dst, table_entry->entry_type);
  switch (table_entry->entry_type) {
    case PI_ACTION_ENTRY_TYPE_NONE:
      break;
    case PI_ACTION_ENTRY_TYPE_DATA:
      s += emit_action_data(dst + s, table_entry->entry.action_data);
      break;
    case PI_ACTION_ENTRY_TYPE_INDIRECT:
      s += emit_indirect_handle(dst + s, table_entry->entry.indirect_handle);
      break;
    default:
      assert(0);
  }
  s += emit_direct_res_config(dst + s, table_entry->direct_res_config);
  // TODO(antonin): properties
  return s;
}

size_t retrieve_action_data(char *src, pi_action_data_t **action_data,
                            int copy) {
  size_t s = 0;
  pi_p4_id_t action_id;
  s += retrieve_p4_id(src, &action_id);
  uint32_t ad_size;
  s += retrieve_uint32(src + s, &ad_size);

  pi_action_data_t *adata;
  if (copy) {
    // no alignment issue with malloc
    char *ad = malloc(sizeof(pi_action_data_t) + ad_size);
    adata = (pi_action_data_t *)ad;
    adata->data = ad + sizeof(pi_action_data_t);
    *action_data = adata;
  } else {
    adata = *action_data;
  }
  adata->p4info = NULL;  // TODO(antonin)
  adata->action_id = action_id;
  adata->data_size = ad_size;

  if (copy) {
    memcpy(adata->data, src + s, ad_size);
  } else {
    adata->data = src + s;
  }

  s += ad_size;

  // TODO(antonin): properties
  return s;
}

size_t retrieve_table_entry(char *src, pi_table_entry_t *table_entry,
                            int copy) {
  size_t s = 0;
  pi_action_entry_type_t entry_type;
  s += retrieve_action_entry_type(src, &entry_type);
  table_entry->entry_type = entry_type;
  switch (entry_type) {
    case PI_ACTION_ENTRY_TYPE_NONE:
      break;
    case PI_ACTION_ENTRY_TYPE_DATA:
      s += retrieve_action_data(src + s, &table_entry->entry.action_data, copy);
      break;
    case PI_ACTION_ENTRY_TYPE_INDIRECT:
      s += retrieve_indirect_handle(src + s,
                                    &table_entry->entry.indirect_handle);
      break;
    default:
      assert(0);
  }
  return s;
}

size_t direct_res_config_size(const pi_direct_res_config_t *direct_res_config) {
  size_t s = sizeof(uint32_t);  // num configs
  if (!direct_res_config) return s;
  for (size_t i = 0; i < direct_res_config->num_configs; i++) {
    s += sizeof(s_pi_p4_id_t);
    s += sizeof(uint32_t);  // deparsed size
    const pi_direct_res_config_one_t *config = &direct_res_config->configs[i];
    pi_res_type_id_t type = PI_GET_TYPE_ID(config->res_id);
    PIDirectResMsgSizeFn msg_size_fn;
    pi_direct_res_get_fns(type, &msg_size_fn, NULL, NULL, NULL);
    s += msg_size_fn(config->config);
  }
  return s;
}

size_t emit_direct_res_config(char *dst,
                              const pi_direct_res_config_t *direct_res_config) {
  size_t num_configs = (direct_res_config) ? direct_res_config->num_configs : 0;
  size_t s = emit_uint32(dst, num_configs);
  for (size_t i = 0; i < num_configs; i++) {
    const pi_direct_res_config_one_t *config = &direct_res_config->configs[i];
    s += emit_p4_id(dst + s, config->res_id);
    pi_res_type_id_t type = PI_GET_TYPE_ID(config->res_id);
    PIDirectResMsgSizeFn msg_size_fn;
    PIDirectResEmitFn emit_fn;
    pi_direct_res_get_fns(type, &msg_size_fn, &emit_fn, NULL, NULL);
    s += emit_uint32(dst + s, msg_size_fn(config->config));
    s += emit_fn(dst + s, config->config);
  }
  return s;
}
