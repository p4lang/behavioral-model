/* Copyright 2019-present Derek So
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
 * Derek So (dts76@cornell.edu)
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
