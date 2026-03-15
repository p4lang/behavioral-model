/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
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
 * Antonin Bas
 *
 */

#include "common.h"

#include <string>

#include "report_error.h"
#include "statusor.h"

namespace pi {

namespace fe {

namespace proto {

namespace common {

namespace {

// count leading zeros in byte
uint8_t clz(uint8_t byte) {
  static constexpr uint8_t clz_table[16] =
      {4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0};
  uint8_t half_byte_hi = byte >> 4;
  uint8_t half_byte_lo = byte & 0x0f;
  return (half_byte_hi == 0) ?
      (4 + clz_table[half_byte_lo]) : clz_table[half_byte_hi];
}

// count trailing zeros in byte
uint8_t ctz(uint8_t b) {
  static constexpr uint8_t ctz_table[16] =
      {4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0};
  uint8_t half_byte_hi = b >> 4;
  uint8_t half_byte_lo = b & 0x0f;
  return (half_byte_lo == 0) ?
      (4 + ctz_table[half_byte_hi]) : ctz_table[half_byte_lo];
}

}  // namespace

StatusOr<std::string> bytestring_p4rt_to_pi(const std::string &str,
                                            size_t nbits) {
  size_t nbytes = (nbits + 7) / 8;
  if (str.size() < nbytes) {
    auto pi_str = str;
    pi_str.insert(0, nbytes - str.size(), 0);
    return pi_str;
  }
  size_t leading_zeros = 0;
  size_t i = 0;
  for (; i < str.size(); i++) {
    if (str[i] != 0) break;
    leading_zeros += 8;
  }
  if (i == str.size()) {
    return std::string(nbytes, 0);
  }
  leading_zeros += static_cast<size_t>(clz(static_cast<uint8_t>(str[i])));
  auto nbits_set = static_cast<size_t>(str.size() * 8 - leading_zeros);
  if (nbits_set > nbits) {
    RETURN_ERROR_STATUS(
        Code::INVALID_ARGUMENT,
        "Bytestring provided does not fit within {} bits",
        nbits);
  }
  return str.substr(str.size() - nbytes);
}

std::string bytestring_pi_to_p4rt(const std::string &str) {
  return bytestring_pi_to_p4rt(str.data(), str.size());
}

std::string bytestring_pi_to_p4rt(const char *str, size_t n) {
  size_t i = 0;
  for (; i < n; i++) {
    if (str[i] != 0) break;
  }
  if (i == n) return std::string(1, 0);
  return std::string(str + i, n - i);
}

Status bytestring_to_pi_port(const std::string &str, pi_port_t* result) {
  if (str.empty()) {
    RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                        "Port must not be the empty string");
  }
  if (str.size() > 4) {
    RETURN_ERROR_STATUS(Code::UNIMPLEMENTED,
                        "Got port of %d bytes, but only 4 bytes are supported",
                        str.size());
  }

  uint32_t value = 0;
  for (char byte : str) {
    value <<= 8;
    value += static_cast<uint8_t>(byte);
  }
  // Casting from unsigned to signed is implementation-defined if the source
  // value would not fit in the destination, so we use memcpy as a work-around.
  static_assert(sizeof(pi_port_t) == 4, "invariant broken");
  memcpy(result, &value, 4);

  if (*result <= 0) {
    RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Port must be non-negative.");
  }
  RETURN_OK_STATUS();
}
std::string pi_port_to_bytestring(pi_port_t port, size_t num_bytes) {
  if (num_bytes == 0) return "";
  std::string result;
  result.resize(num_bytes);
  static_assert(sizeof(pi_port_t) == sizeof(uint32_t), "invariant broken");
  uint32_t value = static_cast<uint32_t>(port);
  for (int i = num_bytes - 1; i >= 0; --i) {
    result[i] = value & 0xffu;
    value >>= 8;
  }
  return result;
}

Code check_proto_bytestring(const std::string &str, size_t nbits) {
  size_t nbytes = (nbits + 7) / 8;
  if (str.size() != nbytes) return Code::INVALID_ARGUMENT;
  size_t zero_nbits = (nbytes * 8) - nbits;
  auto not_zero_pos = static_cast<size_t>(clz(static_cast<uint8_t>(str[0])));
  if (not_zero_pos < zero_nbits) return Code::INVALID_ARGUMENT;
  return Code::OK;
}

bool check_prefix_trailing_zeros(const std::string &str, int pLen) {
  size_t bitwidth = str.size() * 8;
  // must be guaranteed by caller
  assert(pLen >= 0 && static_cast<size_t>(pLen) <= bitwidth);
  size_t trailing_zeros = bitwidth - pLen;
  size_t pos = str.size() - 1;
  for (; trailing_zeros >= 8; trailing_zeros -= 8) {
    if (str[pos] != 0) return false;
    pos--;
  }
  return (trailing_zeros == 0) ||
      (ctz(static_cast<uint8_t>(str[pos])) >= trailing_zeros);
}

std::string range_default_lo(size_t nbits) {
  size_t nbytes = (nbits + 7) / 8;
  return std::string(nbytes, '\x00');
}

std::string range_default_hi(size_t nbits) {
  size_t nbytes = (nbits + 7) / 8;
  std::string hi(nbytes, '\xff');
  size_t zero_nbits = (nbytes * 8) - nbits;
  uint8_t mask = 0xff >> zero_nbits;
  hi[0] &= static_cast<char>(mask);
  assert(check_proto_bytestring(hi, nbits) == Code::OK);
  return hi;
}

}  // namespace common

}  // namespace proto

}  // namespace fe

}  // namespace pi
