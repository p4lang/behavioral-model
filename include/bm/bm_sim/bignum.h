/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef BM_BM_SIM_BIGNUM_H_
#define BM_BM_SIM_BIGNUM_H_

#include <gmp.h>

// will need to implement this ourselves if we do not use Boost
#include <boost/multiprecision/gmp.hpp>

namespace bm {

namespace bignum {

  using boost::multiprecision::gmp_int;
  using boost::multiprecision::number;

  using Bignum = number<gmp_int>;

  inline size_t export_bytes(char *dst, size_t size, const Bignum &src) {
    size_t count;
    mpz_export(dst, &count, 1, size, 1, 0, src.backend().data());
    return count;
  }

  inline size_t export_size_in_bytes(const Bignum &src) {
    return (mpz_sizeinbase(src.backend().data(), 2) + 7) / 8;
  }

  inline void import_bytes(Bignum *dst, const char *src, size_t size) {
    mpz_import(dst->backend().data(), 1, 1, size, 1, 0, src);
  }

  inline int test_bit(const Bignum &v, size_t index) {
    return mpz_tstbit(v.backend().data(), index);
  }

  inline void clear_bit(Bignum *v, size_t index) {
    return mpz_clrbit(v->backend().data(), index);
  }

}  // namespace bignum

}  // namespace bm

#endif  // BM_BM_SIM_BIGNUM_H_
