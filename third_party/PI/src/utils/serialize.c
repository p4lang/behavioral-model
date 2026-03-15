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

#include <PI/int/serialize.h>

#include <stdint.h>
#include <string.h>

size_t emit_uint32(char *dst, uint32_t v) {
  memcpy(dst, &v, sizeof(v));
  return sizeof(v);
}

size_t emit_uint64(char *dst, uint64_t v) {
  memcpy(dst, &v, sizeof(v));
  return sizeof(v);
}

size_t emit_repeated_byte(char *dst, char c, size_t count) {
  memset(dst, c, count);
  return count;
}

size_t emit_p4_id(char *dst, pi_p4_id_t v) { return emit_uint32(dst, v); }

size_t emit_entry_handle(char *dst, pi_entry_handle_t v) {
  return emit_uint64(dst, v);
}

size_t emit_indirect_handle(char *dst, pi_indirect_handle_t v) {
  return emit_uint64(dst, v);
}

size_t emit_dev_id(char *dst, pi_dev_id_t v) { return emit_uint64(dst, v); }

size_t emit_dev_tgt(char *dst, pi_dev_tgt_t v) {
  size_t s = 0;
  s += emit_dev_id(dst, v.dev_id);
  s += emit_uint32(dst + s, v.dev_pipe_mask);
  return s;
}

size_t emit_status(char *dst, pi_status_t v) { return emit_uint32(dst, v); }

size_t emit_session_handle(char *dst, pi_session_handle_t v) {
  return emit_uint32(dst, v);
}

size_t emit_action_entry_type(char *dst, pi_action_entry_type_t v) {
  return emit_uint32(dst, v);
}

size_t emit_counter_value(char *dst, pi_counter_value_t v) {
  return emit_uint64(dst, v);
}

size_t emit_counter_data(char *dst, const pi_counter_data_t *v) {
  size_t s = 0;
  s += emit_uint32(dst, v->valid);
  s += emit_counter_value(dst + s, v->bytes);
  s += emit_counter_value(dst + s, v->packets);
  return s;
}

size_t emit_meter_spec(char *dst, const pi_meter_spec_t *v) {
  size_t s = 0;
  s += emit_uint64(dst, v->cir);
  s += emit_uint32(dst + s, v->cburst);
  s += emit_uint64(dst + s, v->pir);
  s += emit_uint32(dst + s, v->pburst);
  s += emit_uint32(dst + s, v->meter_unit);
  s += emit_uint32(dst + s, v->meter_type);
  return s;
}

size_t emit_learn_msg_id(char *dst, pi_learn_msg_id_t v) {
  return emit_uint64(dst, v);
}

size_t retrieve_uint32(const char *src, uint32_t *v) {
  memcpy(v, src, sizeof(*v));
  return sizeof(*v);
}

size_t retrieve_uint64(const char *src, uint64_t *v) {
  memcpy(v, src, sizeof(*v));
  return sizeof(*v);
}

size_t retrieve_p4_id(const char *src, pi_p4_id_t *v) {
  return retrieve_uint32(src, v);
}

size_t retrieve_entry_handle(const char *src, pi_entry_handle_t *v) {
  return retrieve_uint64(src, v);
}

size_t retrieve_indirect_handle(const char *src, pi_indirect_handle_t *v) {
  return retrieve_uint64(src, v);
}

size_t retrieve_dev_id(const char *src, pi_dev_id_t *v) {
  return retrieve_uint64(src, v);
}

size_t retrieve_dev_tgt(const char *src, pi_dev_tgt_t *v) {
  size_t s = 0;
  s += retrieve_dev_id(src, &v->dev_id);
  uint32_t tmp32;
  s += retrieve_uint32(src + s, &tmp32);
  v->dev_pipe_mask = tmp32;
  return s;
}

size_t retrieve_status(const char *src, pi_status_t *v) {
  return retrieve_uint32(src, v);
}

size_t retrieve_session_handle(const char *src, pi_session_handle_t *v) {
  return retrieve_uint32(src, v);
}

size_t retrieve_action_entry_type(const char *src, pi_action_entry_type_t *v) {
  return retrieve_uint32(src, v);
}

size_t retrieve_counter_value(const char *src, pi_counter_value_t *v) {
  return retrieve_uint64(src, v);
}

size_t retrieve_counter_data(const char *src, pi_counter_data_t *v) {
  size_t s = 0;
  uint32_t tmp32;
  s += retrieve_uint32(src, &tmp32);
  v->valid = tmp32;
  s += retrieve_counter_value(src + s, &v->bytes);
  s += retrieve_counter_value(src + s, &v->packets);
  return s;
}

size_t retrieve_meter_spec(const char *src, pi_meter_spec_t *v) {
  size_t s = 0;
  s += retrieve_uint64(src, &v->cir);
  s += retrieve_uint32(src + s, &v->cburst);
  s += retrieve_uint64(src + s, &v->pir);
  s += retrieve_uint32(src + s, &v->pburst);
  uint32_t tmp32;
  s += retrieve_uint32(src + s, &tmp32);
  v->meter_unit = (pi_meter_unit_t)tmp32;
  s += retrieve_uint32(src + s, &tmp32);
  v->meter_type = (pi_meter_type_t)tmp32;
  return s;
}

size_t retrieve_learn_msg_id(const char *src, pi_learn_msg_id_t *v) {
  // works because pi_learn_msg_id_t is typedef'd from uint64
  return retrieve_uint64(src, v);
}
