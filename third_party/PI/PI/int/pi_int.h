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

#ifndef PI_INT_PI_INT_H_
#define PI_INT_PI_INT_H_

#include "PI/pi.h"

#ifdef __cplusplus
extern "C" {
#endif

// Increment any time a change is made to the PI internal ABI
// Revision history:
//  * 1 -> 2: support for optional match type
//  * 2 -> 3: add PI_STATUS_INIT_ALREADY_CALLED error
#define PI_ABI_VERSION 3

static inline pi_p4_id_t pi_make_action_id(uint16_t index) {
  return (PI_ACTION_ID << 24) | index;
}

static inline pi_p4_id_t pi_make_table_id(uint16_t index) {
  return (PI_TABLE_ID << 24) | index;
}

static inline pi_p4_id_t pi_make_act_prof_id(uint16_t index) {
  return (PI_ACT_PROF_ID << 24) | index;
}

static inline pi_p4_id_t pi_make_counter_id(uint16_t index) {
  return (PI_COUNTER_ID << 24) | index;
}

static inline pi_p4_id_t pi_make_direct_counter_id(uint16_t index) {
  return (PI_DIRECT_COUNTER_ID << 24) | index;
}

static inline pi_p4_id_t pi_make_meter_id(uint16_t index) {
  return (PI_METER_ID << 24) | index;
}

static inline pi_p4_id_t pi_make_direct_meter_id(uint16_t index) {
  return (PI_DIRECT_METER_ID << 24) | index;
}

#define PI_GET_TYPE_ID(id) ((id) >> 24)

// TODO(antonin): find a better location
static inline size_t get_match_key_size_one_field(
    pi_p4info_match_type_t match_type, size_t bitwidth) {
  size_t nbytes = (bitwidth + 7) / 8;
  switch (match_type) {
    case PI_P4INFO_MATCH_TYPE_VALID:
      assert(nbytes == 1);
    case PI_P4INFO_MATCH_TYPE_EXACT:
      return nbytes;
    case PI_P4INFO_MATCH_TYPE_LPM:
      return nbytes + sizeof(uint32_t);
    case PI_P4INFO_MATCH_TYPE_TERNARY:
    case PI_P4INFO_MATCH_TYPE_RANGE:
    case PI_P4INFO_MATCH_TYPE_OPTIONAL:  // treat it as ternary for now
      return 2 * nbytes;
    default:
      assert(0);
  }
  return 0;
}

struct pi_match_key_s {
  const pi_p4info_t *p4info;
  pi_p4_id_t table_id;
  pi_priority_t priority;
  size_t data_size;
  char *data;
};

struct pi_action_data_s {
  const pi_p4info_t *p4info;
  pi_p4_id_t action_id;
  size_t data_size;
  char *data;
};

struct pi_table_fetch_res_s {
  const pi_p4info_t *p4info;
  pi_p4_id_t table_id;  // TODO(antonin): remove?
  size_t num_entries;
  size_t mkey_nbytes;
  size_t idx;
  size_t curr;
  size_t entries_size;
  char *entries;

  // byte buffer to store structs used to represent entries in contiguous memory
  // includes pointers to entries byte buffer
  char *data;
  // size reserved for each entry in data byte buffer
  size_t data_size_per_entry;
  size_t num_direct_resources;
  size_t max_size_of_direct_resources;
};

struct pi_act_prof_fetch_res_s {
  const pi_p4info_t *p4info;
  pi_p4_id_t act_prof_id;  // TODO(antonin): remove?
  size_t num_members;
  size_t num_groups;
  size_t idx_members;
  size_t idx_groups;
  size_t curr_members;
  size_t curr_groups;
  size_t entries_members_size;
  size_t entries_groups_size;
  char *entries_members;
  char *entries_groups;
  size_t num_cumulated_mbr_handles;
  pi_indirect_handle_t *mbr_handles;
  struct pi_action_data_s *action_datas;
};

typedef struct {
  pi_dev_id_t dev_id;
  int backend_id;
  size_t version;
  const pi_p4info_t *p4info;
} pi_device_info_t;

void pi_device_lock();
void pi_device_unlock();

pi_device_info_t *pi_get_device_info(pi_dev_id_t dev_id);
pi_device_info_t *pi_get_devices(size_t *num_devices);

void pi_update_device_config(pi_dev_id_t dev_id, const pi_p4info_t *p4info);
void pi_create_device_config(pi_dev_id_t dev_id);

#ifdef __cplusplus
}
#endif

#endif  // PI_INT_PI_INT_H_
