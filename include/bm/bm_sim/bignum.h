/* Copyright 2013-present Barefoot Networks, Inc.
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

#ifndef BM_BM_SIM_BIGNUM_H_
#define BM_BM_SIM_BIGNUM_H_

#include <boost/multiprecision/cpp_int.hpp>

#include "bytecontainer.h"

namespace bm {

namespace bignum {

  using Bignum = boost::multiprecision::cpp_int;

  inline size_t export_bytes(char *dst, const Bignum &src) {
    boost::multiprecision::export_bits(src, dst, 8);
    return src.backend().size();
  }

  inline size_t export_size_in_bytes(const Bignum &src) {
    return (boost::multiprecision::msb(src) + 7) / 8;
  }

  inline void import_bytes(Bignum *dst, const char *src, size_t size) {
    boost::multiprecision::import_bits(*dst, src, src + size, 8);
  }

  inline int test_bit(const Bignum &v, size_t index) {
    return boost::multiprecision::bit_test(v, index) ? 1 : 0;
  }

  inline void clear_bit(Bignum *v, size_t index) {
    boost::multiprecision::bit_unset(*v, index);
  }

}  // namespace bignum

}  // namespace bm

#endif  // BM_BM_SIM_BIGNUM_H_
