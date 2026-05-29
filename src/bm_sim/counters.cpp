// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/counters.h>

#include <iostream>

namespace bm {

Counter::CounterErrorCode
Counter::query_counter(counter_value_t *bytes, counter_value_t *packets) const {
  *bytes = this->bytes;
  *packets = this->packets;
  return SUCCESS;
}

Counter::CounterErrorCode
Counter::reset_counter() {
  bytes = 0u;
  packets = 0u;
  return SUCCESS;
}

Counter::CounterErrorCode
Counter::write_counter(counter_value_t bytes, counter_value_t packets) {
  this->bytes = bytes;
  this->packets = packets;
  return SUCCESS;
}

void
Counter::serialize(std::ostream *out) const {
  (*out) << bytes << " " << packets << "\n";
}

void
Counter::deserialize(std::istream *in) {
  uint64_t b, p;
  (*in) >> b >> p;
  bytes = b;
  packets = p;
}

Counter::CounterErrorCode
CounterArray::reset_counters() {
  for (Counter &c : counters)
    c.reset_counter();
  return Counter::SUCCESS;
}

}  // namespace bm
