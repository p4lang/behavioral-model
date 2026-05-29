// Copyright 2024 Marvell Technology, Inc.
// SPDX-FileCopyrightText: 2024 Marvell Technology, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Rupesh Chiluka (rchiluka@marvell.com)
 *
 */


#include "pna_counter.h"

namespace bm {

namespace pna {

void
PNA_Counter::count(const Data &index) {
  _counter->get_counter(
      index.get<size_t>()).increment_counter(get_packet());
}

Counter &
PNA_Counter::get_counter(size_t idx) {
  return _counter->get_counter(idx);
}

const Counter &
PNA_Counter::get_counter(size_t idx) const {
  return _counter->get_counter(idx);
}

Counter::CounterErrorCode
PNA_Counter::reset_counters(){
  return _counter->reset_counters();
}

BM_REGISTER_EXTERN_W_NAME(Counter, PNA_Counter);
BM_REGISTER_EXTERN_W_NAME_METHOD(Counter, PNA_Counter, count, const Data &);

}  // namespace bm::pna

}  // namespace bm

int import_counters(){
  return 0;
}
