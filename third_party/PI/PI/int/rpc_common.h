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

#ifndef PI_INT_RPC_COMMON_H_
#define PI_INT_RPC_COMMON_H_

#include "serialize.h"

typedef enum {
  PI_RPC_INIT = 0,
  PI_RPC_ASSIGN_DEVICE,
  PI_RPC_UPDATE_DEVICE_START,
  PI_RPC_UPDATE_DEVICE_END,
  PI_RPC_REMOVE_DEVICE,
  PI_RPC_DESTROY,

  PI_RPC_SESSION_INIT,
  PI_RPC_SESSION_CLEANUP,

  PI_RPC_BATCH_BEGIN,
  PI_RPC_BATCH_END,

  PI_RPC_TABLE_ENTRY_ADD,
  PI_RPC_TABLE_DEFAULT_ACTION_SET,
  PI_RPC_TABLE_DEFAULT_ACTION_RESET,
  PI_RPC_TABLE_DEFAULT_ACTION_GET,
  /* PI_RPC_TABLE_DEFAULT_ACTION_DONE, */
  PI_RPC_TABLE_ENTRY_DELETE,
  PI_RPC_TABLE_ENTRY_DELETE_WKEY,
  PI_RPC_TABLE_ENTRY_MODIFY,
  PI_RPC_TABLE_ENTRY_MODIFY_WKEY,
  PI_RPC_TABLE_ENTRIES_FETCH,
  /* PI_RPC_TABLE_ENTRIES_FETCH_DONE, */

  // act profs
  PI_RPC_ACT_PROF_MBR_CREATE,
  PI_RPC_ACT_PROF_MBR_DELETE,
  PI_RPC_ACT_PROF_MBR_MODIFY,
  PI_RPC_ACT_PROF_GRP_CREATE,
  PI_RPC_ACT_PROF_GRP_DELETE,
  PI_RPC_ACT_PROF_GRP_ADD_MBR,
  PI_RPC_ACT_PROF_GRP_REMOVE_MBR,
  PI_RPC_ACT_PROF_ENTRIES_FETCH,
  /* PI_RPC_ACT_PROF_ENTRIES_FETCH_DONE, */

  // counters
  PI_RPC_COUNTER_READ,
  PI_RPC_COUNTER_READ_DIRECT,
  PI_RPC_COUNTER_WRITE,
  PI_RPC_COUNTER_WRITE_DIRECT,

  // meters
  PI_RPC_METER_READ,
  PI_RPC_METER_READ_DIRECT,
  PI_RPC_METER_SET,
  PI_RPC_METER_SET_DIRECT,

  // learning
  PI_RPC_LEARN_MSG_ACK,

  // packet in/out
  PI_RPC_PACKETOUT_SEND,

  // rpc management
  // retrieve state for sync-up when rpc client is started
  PI_RPC_INT_GET_STATE = 256,
} pi_rpc_type_t;

typedef uint32_t pi_rpc_id_t;
typedef pi_rpc_id_t s_pi_rpc_id_t;

size_t emit_rpc_id(char *dst, pi_rpc_id_t v);
size_t retrieve_rpc_id(const char *src, pi_rpc_id_t *v);

typedef uint32_t s_pi_rpc_type_t;

size_t emit_rpc_type(char *dst, pi_rpc_type_t v);
size_t retrieve_rpc_type(const char *src, pi_rpc_type_t *v);

typedef struct __attribute__((packed)) {
  s_pi_rpc_id_t id;
  s_pi_status_t type;
} rep_hdr_t;

typedef struct __attribute__((packed)) {
  s_pi_rpc_id_t id;
  s_pi_rpc_type_t type;
} req_hdr_t;

struct pi_table_entry_t;

size_t table_entry_size(const pi_table_entry_t *table_entry);
size_t emit_table_entry(char *dst, const pi_table_entry_t *table_entry);
size_t retrieve_table_entry(char *src, pi_table_entry_t *table_entry, int copy);

size_t action_data_size(const pi_action_data_t *action_data);
size_t emit_action_data(char *dst, const pi_action_data_t *action_data);
size_t retrieve_action_data(char *src, pi_action_data_t **action_data,
                            int copy);

size_t direct_res_config_size(const pi_direct_res_config_t *direct_res_config);
size_t emit_direct_res_config(char *dst,
                              const pi_direct_res_config_t *direct_res_config);

// for notifications
// TODO(antonin): different header?
typedef char s_pi_notifications_topic_t[6];

typedef struct __attribute__((packed)) {
  s_pi_notifications_topic_t topic;
  s_pi_dev_tgt_t dev_tgt;
  s_pi_p4_id_t id;
  s_pi_learn_msg_id_t msg_id;
  uint32_t num;
  uint32_t entry_size;
} s_pi_learn_msg_hdr_t;

#endif  // PI_INT_RPC_COMMON_H_
