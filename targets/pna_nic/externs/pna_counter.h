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


#ifndef PNA_NIC_PNA_COUNTER_H_
#define PNA_NIC_PNA_COUNTER_H_

#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/counters.h>

namespace bm {

namespace pna {

class PNA_Counter : public bm::ExternType {
 public:
  static constexpr p4object_id_t spec_id = 0xffffffff;

  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(n_counters);
    BM_EXTERN_ATTRIBUTE_ADD(type);
  }
  
  void init() override {
    _counter = std::unique_ptr<CounterArray>(
        new CounterArray(get_name() + ".$impl",
                         spec_id,
                         n_counters.get<size_t>()));
  }

  void count(const Data &index);

  Counter &get_counter(size_t idx);

  const Counter &get_counter(size_t idx) const;

  Counter::CounterErrorCode reset_counters();

  size_t size() const { return _counter->size(); };

 private:
  Data n_counters;
  Data type;
  std::unique_ptr<CounterArray> _counter;
};

}  // namespace bm::pna

}  // namespace bm

#endif
