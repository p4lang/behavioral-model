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

#include "PI/pi_value.h"
#include "PI/int/pi_int.h"
#include "utils/utils.h"

#include <arpa/inet.h>
#include <assert.h>
#include <string.h>

static inline pi_status_t get_bitwidth_and_mask(const pi_p4info_t *p4info,
                                                pi_p4_id_t parent_id,
                                                pi_p4_id_t obj_id,
                                                size_t *bitwidth, char *mask) {
  switch (PI_GET_TYPE_ID(parent_id)) {
    case PI_ACTION_ID:
      *bitwidth = pi_p4info_action_param_bitwidth(p4info, parent_id, obj_id);
      *mask = pi_p4info_action_param_byte0_mask(p4info, parent_id, obj_id);
      return PI_STATUS_SUCCESS;
    case PI_TABLE_ID:
      *bitwidth =
          pi_p4info_table_match_field_bitwidth(p4info, parent_id, obj_id);
      *mask = pi_p4info_table_match_field_byte0_mask(p4info, parent_id, obj_id);
      return PI_STATUS_SUCCESS;
    default:
      return PI_STATUS_NETV_INVALID_OBJ_ID;
  }
}

// we are masking the extra bits in the first byte
pi_status_t pi_getnetv_u8(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                          pi_p4_id_t obj_id, uint8_t u8, pi_netv_t *fv) {
  size_t bitwidth;
  char byte0_mask;
  pi_status_t rc =
      get_bitwidth_and_mask(p4info, parent_id, obj_id, &bitwidth, &byte0_mask);
  if (rc != PI_STATUS_SUCCESS) return rc;
  if (bitwidth > 8) return PI_STATUS_NETV_INVALID_SIZE;
  fv->is_ptr = 0;
  fv->parent_id = parent_id;
  fv->obj_id = obj_id;
  fv->size = 1;
  u8 &= byte0_mask;
  memcpy(&fv->v.data[0], &u8, 1);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_getnetv_u16(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                           pi_p4_id_t obj_id, uint16_t u16, pi_netv_t *fv) {
  size_t bitwidth;
  char byte0_mask;
  pi_status_t rc =
      get_bitwidth_and_mask(p4info, parent_id, obj_id, &bitwidth, &byte0_mask);
  if (rc != PI_STATUS_SUCCESS) return rc;
  if (bitwidth <= 8 || bitwidth > 16) return PI_STATUS_NETV_INVALID_SIZE;
  fv->is_ptr = 0;
  fv->parent_id = parent_id;
  fv->obj_id = obj_id;
  fv->size = 2;
  u16 = htons(u16);
  char *data = (char *)&u16;
  data[0] &= byte0_mask;
  memcpy(&fv->v.data[0], data, 2);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_getnetv_u32(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                           pi_p4_id_t obj_id, uint32_t u32, pi_netv_t *fv) {
  size_t bitwidth;
  char byte0_mask;
  pi_status_t rc =
      get_bitwidth_and_mask(p4info, parent_id, obj_id, &bitwidth, &byte0_mask);
  if (rc != PI_STATUS_SUCCESS) return rc;
  if (bitwidth <= 16 || bitwidth > 32) return PI_STATUS_NETV_INVALID_SIZE;
  fv->is_ptr = 0;
  fv->parent_id = parent_id;
  fv->obj_id = obj_id;
  fv->size = (bitwidth + 7) / 8;
  u32 = htonl(u32);
  char *data = (char *)&u32;
  data += (4 - fv->size);
  data[0] &= byte0_mask;
  memcpy(&fv->v.data[0], data, fv->size);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_getnetv_u64(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                           pi_p4_id_t obj_id, uint64_t u64, pi_netv_t *fv) {
  size_t bitwidth;
  char byte0_mask;
  pi_status_t rc =
      get_bitwidth_and_mask(p4info, parent_id, obj_id, &bitwidth, &byte0_mask);
  if (rc != PI_STATUS_SUCCESS) return rc;
  if (bitwidth <= 32 || bitwidth > 64) return PI_STATUS_NETV_INVALID_SIZE;
  fv->is_ptr = 0;
  fv->parent_id = parent_id;
  fv->obj_id = obj_id;
  fv->size = (bitwidth + 7) / 8;
  u64 = htonll(u64);
  char *data = (char *)&u64;
  data += (8 - fv->size);
  data[0] &= byte0_mask;
  memcpy(&fv->v.data[0], data, fv->size);
  return PI_STATUS_SUCCESS;
}

// we borrow the pointer, client is still responsible for deleting memory when
// he is done with the value
// unlike for previous cases, I am not masking the first byte, because I do not
// want to write to the client's memory
// FIXME(antonin)
pi_status_t pi_getnetv_ptr(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                           pi_p4_id_t obj_id, const char *ptr, size_t size,
                           pi_netv_t *fv) {
  size_t bitwidth;
  char byte0_mask;
  pi_status_t rc =
      get_bitwidth_and_mask(p4info, parent_id, obj_id, &bitwidth, &byte0_mask);
  if (rc != PI_STATUS_SUCCESS) return rc;
  if (size > 0 && ((bitwidth + 7) / 8 != size))
    return PI_STATUS_NETV_INVALID_SIZE;
  fv->is_ptr = 1;
  fv->parent_id = parent_id;
  fv->obj_id = obj_id;
  fv->size = (bitwidth + 7) / 8;
  fv->v.ptr = ptr;
  return PI_STATUS_SUCCESS;
}
