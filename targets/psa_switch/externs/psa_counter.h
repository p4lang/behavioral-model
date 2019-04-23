
#ifndef PSA_SWITCH_PSA_COUNTER_H_
#define PSA_SWITCH_PSA_COUNTER_H_

#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/counters.h>

namespace bm  {
class PSA_Counter : public bm::ExternType {
 public:
  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(n_counters);
    BM_EXTERN_ATTRIBUTE_ADD(type);
  }
  
  void init() override {
    _counter = std::unique_ptr<CounterArray>(
        new CounterArray(get_name(),
                         get_id(),
                         n_counters.get<size_t>()));
  }

  void count(const Data &index);

  Counter& get_counter(size_t idx);

  const Counter& get_counter(size_t idx) const;

 private:
  Data n_counters;
  Data type;
  std::unique_ptr<CounterArray> _counter;
};
}
#endif
