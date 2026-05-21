// Copyright 2024 Marvell Technology, Inc.
// SPDX-FileCopyrightText: 2024 Marvell Technology, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Rupesh Chiluka (rchiluka@marvell.com)
 *
 */

#include "pna_random.h"
#include <bm/bm_sim/logger.h>

#include <random>
#include <thread>
#include <iostream>

namespace bm {

namespace pna {

void
PNA_Random::init() {
  min_val = min.get_uint64();
  max_val = max.get_uint64();
  _BM_ASSERT((max_val > min_val) && "[Error] Random number range must be positive.");

  /* Note: Even though PNA spec mentioned range should be a power of 2 for
   * max portability, bmv2 does not impose this restriction.
   */
}

void
PNA_Random::read(Data &value) {
  using engine = std::default_random_engine;
  using hash = std::hash<std::thread::id>;
  static thread_local engine generator(hash()(std::this_thread::get_id()));
  using distrib64 = std::uniform_int_distribution<uint64_t>;
  distrib64 distribution(min_val, max_val);
  value.set(distribution(generator));
}

BM_REGISTER_EXTERN_W_NAME(Random, PNA_Random);
BM_REGISTER_EXTERN_W_NAME_METHOD(Random, PNA_Random, read, Data &);

}  // namespace bm::pna

}  // namespace bm

int import_random(){
  return 0;
}
