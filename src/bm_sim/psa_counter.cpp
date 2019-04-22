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


#include <bm/bm_sim/psa_counter.h>
#include <iostream>
#include <vector>

namespace bm {

void
P_Counter::increment_counter(const Packet &pkt) {
  bytes += pkt.get_ingress_length();
  packets += 1;
  std::cout << "Counter: incrementing counter" << std::endl;
}

P_Counter::CounterErrorCode
P_Counter::query_counter(counter_value_t *bytes,
                         counter_value_t *packets) const {
  *bytes = this->bytes;
  *packets = this->packets;
  return SUCCESS;
}

P_Counter::CounterErrorCode
P_Counter::reset_counter() {
  bytes = 0u;
  packets = 0u;
  return SUCCESS;
}

P_Counter::CounterErrorCode
P_Counter::write_counter(counter_value_t bytes, counter_value_t packets) {
  this->bytes = bytes;
  this->packets = packets;
  return SUCCESS;
}

void
P_Counter::serialize(std::ostream *out) const {
  (*out) << bytes << " " << packets << "\n";
}

void
P_Counter::deserialize(std::istream *in) {
  uint64_t b, p;
  (*in) >> b >> p;
  bytes = b;
  packets = p;
}

void
PSA_Counter::init() {
  counters = std::vector<P_Counter>(n_counters.get_uint());
}

P_Counter&
PSA_Counter::get_counter(size_t idx) {
  return counters[idx];
}

const P_Counter&
PSA_Counter::get_counter(size_t idx) const {
  return counters[idx];
}

P_Counter&
PSA_Counter::operator[](size_t idx) {
  assert(idx < size());
  return counters[idx];
}

const P_Counter&
PSA_Counter::operator[](size_t idx) const {
  assert(idx < size());
  return counters[idx];
}

size_t
PSA_Counter::size() const {
  return counters.size();
}

}  // namespace bm
