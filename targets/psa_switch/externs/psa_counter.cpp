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

  Counter::CounterErrorCode count(const Data &index) {
    _counter->get_counter(
        index.get<size_t>()).increment_counter(get_packet());
  }

 private:
  Data n_counters;
  Data type;
  std::unique_ptr<CounterArray> _counter;
};
BM_REGISTER_EXTERN(PSA_Counter);
BM_REGISTER_EXTERN_METHOD(PSA_Counter, count, const Data &);
}

int import_counters() {
  return 0;
}
