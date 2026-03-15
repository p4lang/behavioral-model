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

#ifndef PROTO_SERVER_UINT128_H_
#define PROTO_SERVER_UINT128_H_

#include <cstdint>

#include <iosfwd>
#include <type_traits>

class Uint128 {
 public:
  constexpr Uint128()
      : high_(0), low_(0) { }
  constexpr Uint128(uint64_t high, uint64_t low)
      : high_(high), low_(low) { }
  template<typename T,
           typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
  // we want implicit conversions for increment operator implementations
  constexpr Uint128(T i)  // NOLINT(runtime/explicit)
      : high_(0), low_(i) { }

  Uint128& operator+=(const Uint128 &other) {
    high_ += other.high_;
    uint64_t new_low_ = low_ + other.low_;
    if (new_low_ < low_) high_++;
    low_ = new_low_;
    return *this;
  }

  Uint128 &operator++() {
    *this += 1;
    return *this;
  }

  Uint128 operator++(int) {
    Uint128 tmp(*this);
    *this += 1;
    return tmp;
  }

  Uint128& operator-=(const Uint128 &other) {
    high_ -= other.high_;
    uint64_t new_low_ = low_ - other.low_;
    if (new_low_ > low_) high_--;
    low_ = new_low_;
    return *this;
  }

  Uint128 &operator--() {
    *this -= 1;
    return *this;
  }

  Uint128 operator--(int) {
    Uint128 tmp(*this);
    *this -= 1;
    return tmp;
  }

  friend bool operator==(const Uint128 &a, const Uint128 &b) {
    return (a.high_ == b.high_) && (a.low_ == b.low_);
  }

  friend bool operator!=(const Uint128 &a, const Uint128 &b) {
    return !(a == b);
  }

  friend bool operator<(const Uint128 &a, const Uint128 &b) {
    return (a.high_ < b.high_) || ((a.high_ == b.high_) && (a.low_ < b.low_));
  }

  friend bool operator<=(const Uint128 &a, const Uint128 &b) {
    return (a.high_ < b.high_) || ((a.high_ == b.high_) && (a.low_ <= b.low_));
  }

  friend bool operator>(const Uint128 &a, const Uint128 &b) {
    return !(a <= b);
  }

  friend bool operator>=(const Uint128 &a, const Uint128 &b) {
    return !(a < b);
  }

  friend std::ostream &operator<<(std::ostream &out, const Uint128 &n);

  uint64_t high() const { return high_; }
  uint64_t low() const { return low_; }

 private:
  uint64_t high_;
  uint64_t low_;
};

#endif  // PROTO_SERVER_UINT128_H_
