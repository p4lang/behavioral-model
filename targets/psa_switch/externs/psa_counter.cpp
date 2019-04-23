#include "psa_counter.h"

namespace bm  {

void
PSA_Counter::count(const Data &index) {
  _counter->get_counter(
      index.get<size_t>()).increment_counter(get_packet());
}

Counter&
PSA_Counter::get_counter(size_t idx) {
  return _counter->get_counter(idx);
}

const Counter&
PSA_Counter::get_counter(size_t idx) const {
  return _counter->get_counter(idx);
}


BM_REGISTER_EXTERN(PSA_Counter);
BM_REGISTER_EXTERN_METHOD(PSA_Counter, count, const Data &);
}

int import_counters(){
  return 0;
}
