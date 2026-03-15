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

#ifndef PI_INT_SERIALIZE_H_
#define PI_INT_SERIALIZE_H_

#include <PI/pi_base.h>
#include <PI/pi_counter.h>
#include <PI/pi_learn.h>
#include <PI/pi_meter.h>
#include <PI/pi_tables.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t emit_uint32(char *dst, uint32_t v);
size_t emit_uint64(char *dst, uint64_t v);

size_t emit_repeated_byte(char *dst, char c, size_t count);

typedef pi_p4_id_t s_pi_p4_id_t;
typedef pi_entry_handle_t s_pi_entry_handle_t;
typedef pi_indirect_handle_t s_pi_indirect_handle_t;
typedef uint64_t s_pi_dev_id_t;
typedef struct __attribute__((packed)) {
  s_pi_dev_id_t _dev_id;
  uint32_t _dev_pipe_mask;
} s_pi_dev_tgt_t;
typedef uint32_t s_pi_status_t;
typedef pi_session_handle_t s_pi_session_handle_t;
typedef uint32_t s_pi_action_entry_type_t;
typedef uint64_t s_pi_counter_value_t;
typedef struct __attribute__((packed)) {
  uint32_t valid;
  s_pi_counter_value_t bytes;
  s_pi_counter_value_t packets;
} s_pi_counter_data_t;
typedef struct __attribute__((packed)) {
  uint64_t cir;
  uint32_t cburst;
  uint64_t pir;
  uint32_t pburst;
  uint32_t unit;
  uint32_t type;
} s_pi_meter_spec_t;
typedef uint64_t s_pi_learn_msg_id_t;

size_t emit_p4_id(char *dst, pi_p4_id_t v);
size_t emit_entry_handle(char *dst, pi_entry_handle_t v);
size_t emit_indirect_handle(char *dst, pi_indirect_handle_t v);
size_t emit_dev_id(char *dst, pi_dev_id_t v);
size_t emit_dev_tgt(char *dst, pi_dev_tgt_t v);
size_t emit_status(char *dst, pi_status_t v);
size_t emit_session_handle(char *dst, pi_session_handle_t v);
size_t emit_action_entry_type(char *dst, pi_action_entry_type_t v);
size_t emit_counter_value(char *dst, pi_counter_value_t v);
size_t emit_counter_data(char *dst, const pi_counter_data_t *v);
size_t emit_meter_spec(char *dst, const pi_meter_spec_t *v);
size_t emit_learn_msg_id(char *dst, pi_learn_msg_id_t v);

size_t retrieve_uint32(const char *src, uint32_t *v);
size_t retrieve_uint64(const char *src, uint64_t *v);

size_t retrieve_p4_id(const char *src, pi_p4_id_t *v);
size_t retrieve_entry_handle(const char *src, pi_entry_handle_t *v);
size_t retrieve_indirect_handle(const char *src, pi_entry_handle_t *v);
size_t retrieve_dev_id(const char *src, pi_dev_id_t *v);
size_t retrieve_dev_tgt(const char *src, pi_dev_tgt_t *v);
size_t retrieve_status(const char *src, pi_status_t *v);
size_t retrieve_session_handle(const char *src, pi_session_handle_t *v);
size_t retrieve_action_entry_type(const char *src, pi_action_entry_type_t *v);
size_t retrieve_counter_value(const char *src, pi_counter_value_t *v);
size_t retrieve_counter_data(const char *src, pi_counter_data_t *v);
size_t retrieve_meter_spec(const char *src, pi_meter_spec_t *v);
size_t retrieve_learn_msg_id(const char *src, pi_learn_msg_id_t *v);

#ifdef __cplusplus
}
#endif

#endif  // PI_INT_SERIALIZE_H_
