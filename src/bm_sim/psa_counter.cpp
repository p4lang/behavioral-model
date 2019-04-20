#include <bm/bm_sim/psa_counter.h>
#include <iostream>

namespace bm {

void 
P_Counter::increment_counter(const Packet &pkt) {
  bytes += pkt.get_ingress_length();
  packets += 1;
  std::cout << "Counter: incrementing counter" << std::endl;
}

P_Counter::CounterErrorCode
P_Counter::query_counter(counter_value_t *bytes, counter_value_t *packets) const {
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
  std::cout << "Initializing counter with " << n_counters.get_uint() << std::endl;
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
}

const P_Counter&
PSA_Counter::operator[](size_t idx) const {
  assert(idx < size());
}

size_t
PSA_Counter::size() const {
  return counters.size();
}
}
