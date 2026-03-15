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

#include <arpa/inet.h>

#include <PI/frontends/cpp/tables.h>
#include <PI/p4info.h>

#include <PI/int/pi_int.h>
#include <PI/int/serialize.h>

#include <limits>
#include <string>

#include <cstring>

namespace pi {

namespace {

template <typename T>
T endianness(T v);

template <>
uint8_t endianness(uint8_t v) {
  return v;
}

template <>
int8_t endianness(int8_t v) {
  return v;
}

template <>
uint16_t endianness(uint16_t v) {
  return htons(v);
}

template <>
int16_t endianness(int16_t v) {
  return static_cast<int16_t>(endianness(static_cast<uint16_t>(v)));
}

template <>
uint32_t endianness(uint32_t v) {
  return htonl(v);
}

template <>
int32_t endianness(int32_t v) {
  return static_cast<int32_t>(endianness(static_cast<uint32_t>(v)));
}

// TODO(antonin): portability
#ifndef htonll
uint64_t htonll(uint64_t n) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return n;
#else
  return (((uint64_t)htonl(n)) << 32) + htonl(n >> 32);
#endif
}
#endif  // htonll

template <>
uint64_t endianness(uint64_t v) {
  return htonll(v);
}

template <>
int64_t endianness(int64_t v) {
  return static_cast<int64_t>(endianness(static_cast<uint64_t>(v)));
}

}  // namespace

MatchKeyReader::MatchKeyReader(const pi_match_key_t *match_key)
    : match_key(match_key) { }

error_code_t
MatchKeyReader::read_one(pi_p4_id_t f_id, const char *src,
                         std::string *v) const {
  const size_t bitwidth = pi_p4info_table_match_field_bitwidth(
      match_key->p4info, match_key->table_id, f_id);
  const size_t bytes = (bitwidth + 7) / 8;
  *v = std::string(src, bytes);
  return 0;
}

error_code_t
MatchKeyReader::get_exact(pi_p4_id_t f_id, std::string *key) const {
  size_t offset = pi_p4info_table_match_field_offset(
      match_key->p4info, match_key->table_id, f_id);
  return read_one(f_id, match_key->data + offset, key);
}

error_code_t
MatchKeyReader::get_lpm(pi_p4_id_t f_id, std::string *key,
                        int *prefix_length) const {
  size_t offset = pi_p4info_table_match_field_offset(
      match_key->p4info, match_key->table_id, f_id);
  error_code_t rc;
  auto src = match_key->data + offset;
  rc = read_one(f_id, src, key);
  if (rc) return rc;
  src += key->size();
  uint32_t pLen;
  retrieve_uint32(src, &pLen);
  *prefix_length = static_cast<int>(pLen);
  return 0;
}

error_code_t
MatchKeyReader::get_ternary(pi_p4_id_t f_id, std::string *key,
                            std::string *mask) const {
  size_t offset = pi_p4info_table_match_field_offset(
      match_key->p4info, match_key->table_id, f_id);
  error_code_t rc;
  auto src = match_key->data + offset;
  rc = read_one(f_id, src, key);
  if (rc) return rc;
  src += key->size();
  rc = read_one(f_id, src, mask);
  return rc;
}

error_code_t
MatchKeyReader::get_optional(pi_p4_id_t f_id, std::string *key,
                             bool *is_wildcard) const {
  std::string mask;
  auto rc = get_ternary(f_id, key, &mask);
  if (rc != 0) return rc;
  *is_wildcard = (mask[0] == 0);
  return 0;
}

error_code_t
MatchKeyReader::get_range(pi_p4_id_t f_id, std::string *start,
                          std::string *end) const {
  return get_ternary(f_id, start, end);
}

error_code_t
MatchKeyReader::get_valid(pi_p4_id_t f_id, bool *key) const {
  size_t offset = pi_p4info_table_match_field_offset(
      match_key->p4info, match_key->table_id, f_id);
  auto src = match_key->data + offset;
  *key = (*src != 0);
  return 0;
}

int
MatchKeyReader::get_priority() const {
  return match_key->priority;
}

MatchKey::MatchKey(const pi_p4info_t *p4info, pi_p4_id_t table_id)
    : p4info(p4info), table_id(table_id),
      mk_size(pi_p4info_table_match_key_size(p4info, table_id)),
      _data(sizeof(*match_key) + mk_size),
      match_key(reinterpret_cast<decltype(match_key)>(_data.data())),
      reader(match_key) {
  // std::allocator is using standard new, no alignment issue with the cast
  // above
  match_key->p4info = p4info;
  match_key->table_id = table_id;
  match_key->priority = 0;
  match_key->data_size = mk_size;
  match_key->data = _data.data() + sizeof(*match_key);
}

MatchKey::MatchKey(const pi_match_key_t *pi_match_key)
    : p4info(pi_match_key->p4info), table_id(pi_match_key->table_id),
      mk_size(pi_match_key->data_size),
      _data(sizeof(*match_key) + mk_size),
      match_key(reinterpret_cast<decltype(match_key)>(_data.data())),
      reader(match_key) {
  *match_key = *pi_match_key;
  match_key->data = _data.data() + sizeof(*match_key);
  memcpy(match_key->data, pi_match_key->data, mk_size);
}

MatchKey::~MatchKey() = default;

void
MatchKey::reset() {
  match_key->priority = 0;
  memset(_data.data(), 0, _data.size());
}

void
MatchKey::from(const pi_match_key_t *pi_match_key) {
  assert(p4info == pi_match_key->p4info);
  assert(table_id == pi_match_key->table_id);
  assert(mk_size == pi_match_key->data_size);
  *match_key = *pi_match_key;
  match_key->data = _data.data() + sizeof(*match_key);
  memcpy(match_key->data, pi_match_key->data, mk_size);
}

pi_p4_id_t
MatchKey::get_table_id() const {
    return table_id;
}

void
MatchKey::set_priority(int priority) {
  match_key->priority = priority;
}

int
MatchKey::get_priority() const {
  return reader.get_priority();
}

void
MatchKey::set_is_default(bool is_default) {
  this->is_default = is_default;
}

bool
MatchKey::get_is_default() const {
  return is_default;
}

template <typename T>
error_code_t
MatchKey::format(pi_p4_id_t f_id, T v, size_t offset, size_t *written) {
  constexpr size_t type_bitwidth = sizeof(T) * 8;
  const size_t bitwidth = pi_p4info_table_match_field_bitwidth(
      p4info, table_id, f_id);
  const size_t bytes = (bitwidth + 7) / 8;
  const char byte0_mask = pi_p4info_table_match_field_byte0_mask(
      p4info, table_id, f_id);
  if (bitwidth > type_bitwidth) return 1;
  v = endianness(v);
  char *data = reinterpret_cast<char *>(&v);
  data += sizeof(T) - bytes;
  data[0] &= byte0_mask;
  memcpy(match_key->data + offset, data, bytes);
  *written = bytes;
  return 0;
}

error_code_t
MatchKey::format(pi_p4_id_t f_id, const char *ptr, size_t s, size_t offset,
                 size_t *written) {
  // constexpr size_t type_bitwidth = sizeof(T) * 8;
  const size_t bitwidth = pi_p4info_table_match_field_bitwidth(
      p4info, table_id, f_id);
  const size_t bytes = (bitwidth + 7) / 8;
  const char byte0_mask = pi_p4info_table_match_field_byte0_mask(
      p4info, table_id, f_id);
  if (bytes != s) return 1;
  char *dst = match_key->data + offset;
  memcpy(dst, ptr, bytes);
  dst[0] &= byte0_mask;
  *written = bytes;
  return 0;
}

template <typename T>
typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
MatchKey::set_exact(pi_p4_id_t f_id, T key) {
  // explicit instantiation below so compile time check not possible
  assert((!std::is_signed<T>::value) && "signed fields not supported yet");
  size_t offset = pi_p4info_table_match_field_offset(p4info, table_id, f_id);
  size_t written = 0;
  return format(f_id, key, offset, &written);
}

template error_code_t MatchKey::set_exact<uint8_t>(pi_p4_id_t, uint8_t);
template error_code_t MatchKey::set_exact<uint16_t>(pi_p4_id_t, uint16_t);
template error_code_t MatchKey::set_exact<uint32_t>(pi_p4_id_t, uint32_t);
template error_code_t MatchKey::set_exact<uint64_t>(pi_p4_id_t, uint64_t);
template error_code_t MatchKey::set_exact<int8_t>(pi_p4_id_t, int8_t);
template error_code_t MatchKey::set_exact<int16_t>(pi_p4_id_t, int16_t);
template error_code_t MatchKey::set_exact<int32_t>(pi_p4_id_t, int32_t);
template error_code_t MatchKey::set_exact<int64_t>(pi_p4_id_t, int64_t);

error_code_t
MatchKey::set_exact(pi_p4_id_t f_id, const char *key, size_t s) {
  size_t offset = pi_p4info_table_match_field_offset(p4info, table_id, f_id);
  size_t written = 0;
  return format(f_id, key, s, offset, &written);
}

error_code_t
MatchKey::get_exact(pi_p4_id_t f_id, std::string *key) const {
  return reader.get_exact(f_id, key);
}

template <typename T>
typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
MatchKey::set_lpm(pi_p4_id_t f_id, T key, int prefix_length) {
  // explicit instantiation below so compile time check not possible
  assert((!std::is_signed<T>::value) && "signed fields not supported yet");
  size_t offset = pi_p4info_table_match_field_offset(p4info, table_id, f_id);
  size_t written = 0;
  error_code_t rc;
  rc = format(f_id, key, offset, &written);
  offset += written;
  emit_uint32(match_key->data + offset, prefix_length);
  return rc;
}

template error_code_t MatchKey::set_lpm<uint8_t>(pi_p4_id_t, uint8_t, int);
template error_code_t MatchKey::set_lpm<uint16_t>(pi_p4_id_t, uint16_t, int);
template error_code_t MatchKey::set_lpm<uint32_t>(pi_p4_id_t, uint32_t, int);
template error_code_t MatchKey::set_lpm<uint64_t>(pi_p4_id_t, uint64_t, int);
template error_code_t MatchKey::set_lpm<int8_t>(pi_p4_id_t, int8_t, int);
template error_code_t MatchKey::set_lpm<int16_t>(pi_p4_id_t, int16_t, int);
template error_code_t MatchKey::set_lpm<int32_t>(pi_p4_id_t, int32_t, int);
template error_code_t MatchKey::set_lpm<int64_t>(pi_p4_id_t, int64_t, int);

error_code_t
MatchKey::set_lpm(pi_p4_id_t f_id, const char *key, size_t s,
                  int prefix_length) {
  size_t offset = pi_p4info_table_match_field_offset(p4info, table_id, f_id);
  size_t written = 0;
  error_code_t rc;
  rc = format(f_id, key, s, offset, &written);
  offset += written;
  emit_uint32(match_key->data + offset, prefix_length);
  return rc;
}

error_code_t
MatchKey::get_lpm(pi_p4_id_t f_id, std::string *key, int *prefix_length) const {
  return reader.get_lpm(f_id, key, prefix_length);
}

template <typename T>
typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
MatchKey::set_ternary(pi_p4_id_t f_id, T key, T mask) {
  // explicit instantiation below so compile time check not possible
  assert((!std::is_signed<T>::value) && "signed fields not supported yet");
  size_t offset = pi_p4info_table_match_field_offset(p4info, table_id, f_id);
  size_t written = 0;
  error_code_t rc;
  rc = format(f_id, key, offset, &written);
  offset += written;
  if (rc) return rc;
  rc = format(f_id, mask, offset, &written);
  return rc;
}

template error_code_t MatchKey::set_ternary<uint8_t>(pi_p4_id_t, uint8_t,
                                                     uint8_t);
template error_code_t MatchKey::set_ternary<uint16_t>(pi_p4_id_t, uint16_t,
                                                      uint16_t);
template error_code_t MatchKey::set_ternary<uint32_t>(pi_p4_id_t, uint32_t,
                                                      uint32_t);
template error_code_t MatchKey::set_ternary<uint64_t>(pi_p4_id_t, uint64_t,
                                                      uint64_t);
template error_code_t MatchKey::set_ternary<int8_t>(pi_p4_id_t, int8_t,
                                                    int8_t);
template error_code_t MatchKey::set_ternary<int16_t>(pi_p4_id_t, int16_t,
                                                     int16_t);
template error_code_t MatchKey::set_ternary<int32_t>(pi_p4_id_t, int32_t,
                                                     int32_t);
template error_code_t MatchKey::set_ternary<int64_t>(pi_p4_id_t, int64_t,
                                                     int64_t);

error_code_t
MatchKey::set_ternary(pi_p4_id_t f_id, const char *key, const char *mask,
                      size_t s) {
  size_t offset = pi_p4info_table_match_field_offset(p4info, table_id, f_id);
  size_t written = 0;
  error_code_t rc;
  rc = format(f_id, key, s, offset, &written);
  if (rc) return rc;
  offset += written;
  rc = format(f_id, mask, s, offset, &written);
  return rc;
}

error_code_t
MatchKey::get_ternary(pi_p4_id_t f_id, std::string *key,
                      std::string *mask) const {
  return reader.get_ternary(f_id, key, mask);
}

template <typename T>
typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
MatchKey::set_optional(pi_p4_id_t f_id, T key, bool is_wildcard) {
  // we rely on the fact that set_ternary does not perform any check for the
  // match type of f_id.
  if (is_wildcard) {
    return set_ternary(f_id, key, static_cast<T>(0));
  }
  // format method will apply the appropriate byte0 mask.
  auto mask = std::numeric_limits<T>::max();
  return set_ternary(f_id, key, mask);
}

template error_code_t MatchKey::set_optional<uint8_t>(pi_p4_id_t, uint8_t,
                                                      bool);
template error_code_t MatchKey::set_optional<uint16_t>(pi_p4_id_t, uint16_t,
                                                       bool);
template error_code_t MatchKey::set_optional<uint32_t>(pi_p4_id_t, uint32_t,
                                                       bool);
template error_code_t MatchKey::set_optional<uint64_t>(pi_p4_id_t, uint64_t,
                                                       bool);
template error_code_t MatchKey::set_optional<int8_t>(pi_p4_id_t, int8_t,
                                                     bool);
template error_code_t MatchKey::set_optional<int16_t>(pi_p4_id_t, int16_t,
                                                      bool);
template error_code_t MatchKey::set_optional<int32_t>(pi_p4_id_t, int32_t,
                                                      bool);
template error_code_t MatchKey::set_optional<int64_t>(pi_p4_id_t, int64_t,
                                                      bool);

error_code_t
MatchKey::set_optional(pi_p4_id_t f_id, const char *key, size_t s,
                       bool is_wildcard) {
  // format method will apply the appropriate byte0 mask.
  std::string mask(s, is_wildcard ? '\x00' : '\xff');
  return set_ternary(f_id, key, mask.data(), s);
}

error_code_t
MatchKey::get_optional(pi_p4_id_t f_id, std::string *key,
                       bool *is_wildcard) const {
  return reader.get_optional(f_id, key, is_wildcard);
}

template <typename T>
typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
MatchKey::set_range(pi_p4_id_t f_id, T start, T end) {
  return set_ternary(f_id, start, end);
}

template error_code_t MatchKey::set_range<uint8_t>(pi_p4_id_t, uint8_t,
                                                   uint8_t);
template error_code_t MatchKey::set_range<uint16_t>(pi_p4_id_t, uint16_t,
                                                    uint16_t);
template error_code_t MatchKey::set_range<uint32_t>(pi_p4_id_t, uint32_t,
                                                    uint32_t);
template error_code_t MatchKey::set_range<uint64_t>(pi_p4_id_t, uint64_t,
                                                    uint64_t);
template error_code_t MatchKey::set_range<int8_t>(pi_p4_id_t, int8_t,
                                                  int8_t);
template error_code_t MatchKey::set_range<int16_t>(pi_p4_id_t, int16_t,
                                                   int16_t);
template error_code_t MatchKey::set_range<int32_t>(pi_p4_id_t, int32_t,
                                                   int32_t);
template error_code_t MatchKey::set_range<int64_t>(pi_p4_id_t, int64_t,
                                                   int64_t);

error_code_t
MatchKey::set_range(pi_p4_id_t f_id, const char *start, const char *end,
                    size_t s) {
  return set_ternary(f_id, start, end, s);
}

error_code_t
MatchKey::get_range(pi_p4_id_t f_id, std::string *start,
                    std::string *end) const {
  return reader.get_range(f_id, start, end);
}

error_code_t
MatchKey::set_valid(pi_p4_id_t f_id, bool key) {
  size_t offset = pi_p4info_table_match_field_offset(p4info, table_id, f_id);
  auto dst = match_key->data + offset;
  *dst = key ? 1 : 0;
  return 0;
}

error_code_t
MatchKey::get_valid(pi_p4_id_t f_id, bool *key) const {
  return reader.get_valid(f_id, key);
}

MatchKey::MatchKey(const MatchKey &other)
    : p4info(other.p4info),
      table_id(other.table_id),
      is_default(other.is_default),
      mk_size(other.mk_size),
      _data(other._data),
      match_key(reinterpret_cast<decltype(match_key)>(_data.data())),
      reader(match_key) {
  match_key->data = _data.data() + sizeof(*match_key);
}

MatchKey &
MatchKey::operator=(const MatchKey &other) {
  MatchKey tmp(other);  // re-use copy-constructor
  *this = std::move(tmp);  // re-use move-assignment
  return *this;
}

size_t
MatchKeyHash::operator()(const MatchKey &mk) const {
  // compute Jenkins hash
  // see https://en.wikipedia.org/wiki/Jenkins_hash_function
  // "seed", maybe not the best choice...
  uint32_t hash = mk.table_id ^ mk.match_key->priority;
  for (size_t i = 0; i < mk.mk_size; i++) {
    hash += mk.match_key->data[i];
    hash += hash << 10;
    hash ^= hash >> 6;
  }
  {
    hash += static_cast<char>(mk.is_default);
    hash += hash << 10;
    hash ^= hash >> 6;
  }
  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;
  return static_cast<size_t>(hash);
}

bool
MatchKeyEq::operator()(const MatchKey &mk1, const MatchKey &mk2) const {
  return (mk1.table_id == mk2.table_id)
      && (mk1.is_default == mk2.is_default)
      && (mk1.match_key->priority == mk2.match_key->priority)
      && (!std::memcmp(mk1.match_key->data, mk2.match_key->data, mk1.mk_size));
}

ActionDataReader::ActionDataReader(const pi_action_data_t *action_data)
    : action_data(action_data) { }

error_code_t
ActionDataReader::get_arg(pi_p4_id_t ap_id, std::string *arg) const {
  const size_t offset = pi_p4info_action_param_offset(
      action_data->p4info, action_data->action_id, ap_id);
  const size_t bitwidth = pi_p4info_action_param_bitwidth(
      action_data->p4info, action_data->action_id, ap_id);
  const size_t bytes = (bitwidth + 7) / 8;
  *arg = std::string(action_data->data + offset, bytes);
  return 0;
}

pi_p4_id_t
ActionDataReader::get_action_id() const {
  return action_data->action_id;
}

ActionData::ActionData(const pi_p4info_t *p4info, pi_p4_id_t action_id)
    : p4info(p4info), action_id(action_id),
      ad_size(pi_p4info_action_data_size(p4info, action_id)),
      _data(sizeof(*action_data) + ad_size),
      action_data(reinterpret_cast<decltype(action_data)>(_data.data())),
      reader(action_data) {
  // using standard new, no alignment issue with cast above
  action_data->p4info = p4info;
  action_data->action_id = action_id;
  action_data->data_size = ad_size;
  action_data->data = _data.data() + sizeof(*action_data);
}

ActionData::~ActionData() { }

void
ActionData::reset() {
  memset(_data.data(), 0, _data.size());
}

pi_p4_id_t ActionData::get_action_id() const {
    return action_id;
}

template <typename T>
error_code_t
ActionData::format(pi_p4_id_t ap_id, T v) {
  constexpr size_t type_bitwidth = sizeof(T) * 8;
  const size_t offset = pi_p4info_action_param_offset(p4info, action_id, ap_id);
  const size_t bitwidth = pi_p4info_action_param_bitwidth(
      p4info, action_id, ap_id);
  const size_t bytes = (bitwidth + 7) / 8;
  const char byte0_mask = pi_p4info_action_param_byte0_mask(
      p4info, action_id, ap_id);
  if (bitwidth > type_bitwidth) return 1;
  v = endianness(v);
  char *data = reinterpret_cast<char *>(&v);
  data += sizeof(T) - bytes;
  data[0] &= byte0_mask;
  memcpy(action_data->data + offset, data, bytes);
  return 0;
}

error_code_t
ActionData::format(pi_p4_id_t ap_id, const char *ptr, size_t s) {
  // constexpr size_t type_bitwidth = sizeof(T) * 8;
  const size_t offset = pi_p4info_action_param_offset(p4info, action_id, ap_id);
  const size_t bitwidth = pi_p4info_action_param_bitwidth(
      p4info, action_id, ap_id);
  const size_t bytes = (bitwidth + 7) / 8;
  const char byte0_mask = pi_p4info_action_param_byte0_mask(
      p4info, action_id, ap_id);
  if (bytes != s) return 1;
  char *dst = action_data->data + offset;
  memcpy(dst, ptr, bytes);
  dst[0] &= byte0_mask;
  return 0;
}

template <typename T>
typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
ActionData::set_arg(pi_p4_id_t ap_id, T arg) {
  // explicit instantiation below so compile time check not possible
  assert((!std::is_signed<T>::value) && "signed params not supported yet");
  return format(ap_id, arg);
}

error_code_t
ActionData::set_arg(pi_p4_id_t ap_id, const char *arg, size_t s) {
  return format(ap_id, arg, s);
}

template error_code_t ActionData::set_arg<uint8_t>(pi_p4_id_t, uint8_t);
template error_code_t ActionData::set_arg<uint16_t>(pi_p4_id_t, uint16_t);
template error_code_t ActionData::set_arg<uint32_t>(pi_p4_id_t, uint32_t);
template error_code_t ActionData::set_arg<uint64_t>(pi_p4_id_t, uint64_t);
template error_code_t ActionData::set_arg<int8_t>(pi_p4_id_t, int8_t);
template error_code_t ActionData::set_arg<int16_t>(pi_p4_id_t, int16_t);
template error_code_t ActionData::set_arg<int32_t>(pi_p4_id_t, int32_t);
template error_code_t ActionData::set_arg<int64_t>(pi_p4_id_t, int64_t);

error_code_t
ActionData::get_arg(pi_p4_id_t ap_id, std::string *arg) const {
  return reader.get_arg(ap_id, arg);
}

ActionData::ActionData(const ActionData &other)
    : p4info(other.p4info),
      action_id(other.action_id),
      ad_size(other.ad_size),
      _data(other._data),
      action_data(reinterpret_cast<decltype(action_data)>(_data.data())),
      reader(action_data) {
  action_data->data = _data.data() + sizeof(*action_data);
}

ActionData &
ActionData::operator=(const ActionData &other) {
  ActionData tmp(other);  // re-use copy-constructor
  *this = std::move(tmp);  // re-use move-assignment
  return *this;
}


MatchTable::MatchTable(pi_session_handle_t sess, pi_dev_tgt_t dev_tgt,
                       const pi_p4info_t *p4info, pi_p4_id_t table_id)
    : sess(sess), dev_tgt(dev_tgt), p4info(p4info), table_id(table_id) { }

pi_table_entry_t
MatchTable::build_table_entry(const ActionEntry &action_entry) const {
  pi_table_entry_t entry;
  entry.entry_properties = &action_entry.properties;
  // TODO(antonin): we could simply use entry.direct_res_config =
  // &action_entry.direct_config? Is it better to use a NULL pointer when the
  // direct resource list is empty?
  entry.direct_res_config = (action_entry.direct_config.num_configs == 0) ?
      NULL : &action_entry.direct_config;

  switch (action_entry.type()) {
    case ActionEntry::Tag::NONE:
      assert(0);
      break;
    case ActionEntry::Tag::ACTION_DATA:
      entry.entry_type = PI_ACTION_ENTRY_TYPE_DATA;
      entry.entry.action_data = action_entry.action_data().get();
      break;
    case ActionEntry::Tag::INDIRECT_HANDLE:
      entry.entry_type = PI_ACTION_ENTRY_TYPE_INDIRECT;
      entry.entry.indirect_handle = action_entry.indirect_handle();
      break;
  }

  return entry;
}

pi_status_t
MatchTable::entry_add(const MatchKey &match_key,
                      const ActionEntry &action_entry, bool overwrite,
                      pi_entry_handle_t *entry_handle) {
  auto entry = build_table_entry(action_entry);
  return pi_table_entry_add(sess, dev_tgt, table_id, match_key.get(),
                            &entry, overwrite, entry_handle);
}

pi_status_t
MatchTable::entry_add(const MatchKey &match_key,
                      const ActionData &action_data, bool overwrite,
                      pi_entry_handle_t *entry_handle) {
  pi_table_entry_t entry;
  entry.entry_properties = NULL;
  entry.direct_res_config = NULL;
  entry.entry_type = PI_ACTION_ENTRY_TYPE_DATA;
  entry.entry.action_data = action_data.get();
  return pi_table_entry_add(sess, dev_tgt, table_id, match_key.get(),
                            &entry, overwrite, entry_handle);
}

pi_status_t
MatchTable::entry_delete(pi_entry_handle_t entry_handle) {
  return pi_table_entry_delete(sess, dev_tgt.dev_id, table_id, entry_handle);
}

pi_status_t
MatchTable::entry_delete_wkey(const MatchKey &match_key) {
  return pi_table_entry_delete_wkey(sess, dev_tgt, table_id, match_key.get());
}

pi_status_t
MatchTable::entry_modify(pi_entry_handle_t entry_handle,
                         const ActionEntry &action_entry) {
  auto entry = build_table_entry(action_entry);
  return pi_table_entry_modify(sess, dev_tgt.dev_id, table_id, entry_handle,
                               &entry);
}

pi_status_t
MatchTable::entry_modify_wkey(const MatchKey &match_key,
                              const ActionEntry &action_entry) {
  auto entry = build_table_entry(action_entry);
  return pi_table_entry_modify_wkey(
      sess, dev_tgt, table_id, match_key.get(), &entry);
}

pi_status_t
MatchTable::default_entry_set(const ActionEntry &action_entry) {
  auto entry = build_table_entry(action_entry);
  return pi_table_default_action_set(sess, dev_tgt, table_id, &entry);
}

pi_status_t
MatchTable::default_entry_reset() {
  return pi_table_default_action_reset(sess, dev_tgt, table_id);
}

pi_status_t
MatchTable::default_entry_set(const ActionData &action_data) {
  pi_table_entry_t entry;
  entry.entry_type = PI_ACTION_ENTRY_TYPE_DATA;
  entry.entry.action_data = action_data.get();
  entry.entry_properties = NULL;
  entry.direct_res_config = NULL;
  return pi_table_default_action_set(sess, dev_tgt, table_id, &entry);
}

ActProf::ActProf(pi_session_handle_t sess, pi_dev_tgt_t dev_tgt,
                 const pi_p4info_t *p4info, pi_p4_id_t act_prof_id)
    : sess(sess), dev_tgt(dev_tgt), p4info(p4info), act_prof_id(act_prof_id) { }

pi_status_t
ActProf::member_create(const ActionData &action_data,
                       pi_indirect_handle_t *member_handle) {
  return pi_act_prof_mbr_create(sess, dev_tgt, act_prof_id, action_data.get(),
                                member_handle);
}

pi_status_t
ActProf::member_delete(pi_indirect_handle_t member_handle) {
  return pi_act_prof_mbr_delete(sess, dev_tgt.dev_id, act_prof_id,
                                member_handle);
}

pi_status_t
ActProf::member_modify(pi_indirect_handle_t member_handle,
                       const ActionData &action_data) {
  return pi_act_prof_mbr_modify(sess, dev_tgt.dev_id, act_prof_id,
                                member_handle, action_data.get());
}

pi_status_t
ActProf::group_create(size_t max_size, pi_indirect_handle_t *group_handle) {
  return pi_act_prof_grp_create(sess, dev_tgt, act_prof_id, max_size,
                                group_handle);
}

pi_status_t
ActProf::group_delete(pi_indirect_handle_t group_handle) {
  return pi_act_prof_grp_delete(sess, dev_tgt.dev_id, act_prof_id,
                                group_handle);
}

pi_status_t
ActProf::group_add_member(pi_indirect_handle_t group_handle,
                          pi_indirect_handle_t member_handle) {
  return pi_act_prof_grp_add_mbr(sess, dev_tgt.dev_id, act_prof_id,
                                 group_handle, member_handle);
}

pi_status_t
ActProf::group_remove_member(pi_indirect_handle_t group_handle,
                             pi_indirect_handle_t member_handle) {
  return pi_act_prof_grp_remove_mbr(sess, dev_tgt.dev_id, act_prof_id,
                                    group_handle, member_handle);
}

pi_status_t
ActProf::group_set_members(pi_indirect_handle_t group_handle,
                           size_t num_members,
                           const pi_indirect_handle_t *member_handles,
                           const bool *activate) {
  return pi_act_prof_grp_set_mbrs(sess, dev_tgt.dev_id, act_prof_id,
                                  group_handle, num_members, member_handles,
                                  activate);
}

pi_status_t
ActProf::group_activate_member(pi_indirect_handle_t group_handle,
                               pi_indirect_handle_t member_handle) {
  return pi_act_prof_grp_activate_mbr(sess, dev_tgt.dev_id, act_prof_id,
                                      group_handle, member_handle);
}

pi_status_t
ActProf::group_deactivate_member(pi_indirect_handle_t group_handle,
                                 pi_indirect_handle_t member_handle) {
  return pi_act_prof_grp_deactivate_mbr(sess, dev_tgt.dev_id, act_prof_id,
                                        group_handle, member_handle);
}

}  // namespace pi
