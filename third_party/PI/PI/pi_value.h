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

//! @file
//! This is needed by the C generic frontend. Can probably use some improvement.

#ifndef PI_INC_PI_PI_VALUE_H_
#define PI_INC_PI_PI_VALUE_H_

#include <PI/p4info.h>

#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  PI_VALUE_TYPE_U8 = 0,
  PI_VALUE_TYPE_U16,
  PI_VALUE_TYPE_U32,
  PI_VALUE_TYPE_U64,
  PI_VALUE_TYPE_PTR,
} pi_value_type_t;

/* 64 bit option can be disabled for 32-bit architecture */
/* implementation can be hidden from user */
//! Used to efficiently represent any integral value, in network-byte order.
typedef struct {
  uint32_t type_and_size;  // first byte is type, rest is size
  union {
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    const char *ptr;
  } value;
} pi_value_t;

static inline void pi_getv_u8(const uint8_t u8, pi_value_t *v) {
  v->type_and_size = ((uint8_t)PI_VALUE_TYPE_U8) << 24;
  v->value.u8 = u8;
}

static inline void pi_getv_u16(const uint16_t u16, pi_value_t *v) {
  v->type_and_size = ((uint8_t)PI_VALUE_TYPE_U16) << 24;
  v->value.u16 = u16;
}

static inline void pi_getv_u32(const uint32_t u32, pi_value_t *v) {
  v->type_and_size = ((uint8_t)PI_VALUE_TYPE_U32) << 24;
  v->value.u32 = u32;
}

static inline void pi_getv_u64(const uint64_t u64, pi_value_t *v) {
  v->type_and_size = ((uint8_t)PI_VALUE_TYPE_U64) << 24;
  v->value.u64 = u64;
}

// we borrow the pointer, client is still responsible for deleting memory when
// he is done with the value
static inline void pi_getv_ptr(const char *ptr, uint32_t size, pi_value_t *v) {
  assert(size < (1 << 24));
  v->type_and_size = ((uint8_t)PI_VALUE_TYPE_PTR) << 24;
  v->type_and_size |= size;
  v->value.ptr = ptr;
}

// in byte order
typedef struct {
  int is_ptr;
  pi_p4_id_t parent_id;
  pi_p4_id_t obj_id;
  size_t size;
  union {
    char data[8];
    const char *ptr;
  } v;
} pi_netv_t;

pi_status_t pi_getnetv_u8(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                          pi_p4_id_t obj_id, uint8_t u8, pi_netv_t *fv);

pi_status_t pi_getnetv_u16(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                           pi_p4_id_t obj_id, uint16_t u16, pi_netv_t *fv);

pi_status_t pi_getnetv_u32(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                           pi_p4_id_t obj_id, uint32_t u32, pi_netv_t *fv);

pi_status_t pi_getnetv_u64(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                           pi_p4_id_t obj_id, uint64_t u64, pi_netv_t *fv);

// we borrow the pointer, client is still responsible for deleting memory when
// he is done with the value
// unlike for previous cases, I am not masking the first byte, because I do not
// want to write to the client's memory
// FIXME(antonin)
pi_status_t pi_getnetv_ptr(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                           pi_p4_id_t obj_id, const char *ptr, size_t size,
                           pi_netv_t *fv);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_VALUE_H_
