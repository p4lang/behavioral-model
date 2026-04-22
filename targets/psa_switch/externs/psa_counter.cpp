// SPDX-FileCopyrightText: 2019 Derek So
// Copyright 2019-present Derek So
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Derek So (dts76@cornell.edu)
 *
 */


#include "psa_counter.h"

namespace bm {

namespace psa {

void
PSA_Counter::count(const Data &index) {
  _counter->get_counter(
      index.get<size_t>()).increment_counter(get_packet());
}

Counter &
PSA_Counter::get_counter(size_t idx) {
  return _counter->get_counter(idx);
}

const Counter &
PSA_Counter::get_counter(size_t idx) const {
  return _counter->get_counter(idx);
}

Counter::CounterErrorCode
PSA_Counter::reset_counters(){
  return _counter->reset_counters();
}

BM_REGISTER_EXTERN_W_NAME(Counter, PSA_Counter);
BM_REGISTER_EXTERN_W_NAME_METHOD(Counter, PSA_Counter, count, const Data &);

}  // namespace bm::psa

}  // namespace bm

int import_counters(){
  return 0;
}
