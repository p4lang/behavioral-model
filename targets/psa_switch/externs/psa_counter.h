/*
 * SPDX-FileCopyrightText: 2019 Derek So
 * Copyright 2019-present Derek So
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Derek So (dts76@cornell.edu)
 *
 */


#ifndef PSA_SWITCH_PSA_COUNTER_H_
#define PSA_SWITCH_PSA_COUNTER_H_

#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/counters.h>

namespace bm {

namespace psa {

class PSA_Counter : public bm::ExternType {
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

}  // namespace bm::psa

}  // namespace bm

#endif
