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



#ifndef BM_BM_SIM_PSA_COUNTER_H_
#define BM_BM_SIM_PSA_COUNTER_H_

#include <vector>

#include "extern.h"
#include "named_p4object.h"
#include "packet.h"


namespace bm {

class P_Counter {
 public:
  using counter_value_t = uint64_t;

  enum CounterErrorCode {
    SUCCESS = 0,
    INVALID_COUNTER_NAME,
    INVALID_INDEX,
    ERROR
  };

  void increment_counter(const Packet &pkt);
  CounterErrorCode query_counter(counter_value_t *bytes,
                                 counter_value_t *packets) const;
  CounterErrorCode reset_counter();
  CounterErrorCode write_counter(counter_value_t bytes,
                                 counter_value_t packets);

  void serialize(std::ostream *out) const;
  void deserialize(std::istream *in);

 private:
  std::atomic<std::uint_fast64_t> bytes{0u};
  std::atomic<std::uint_fast64_t> packets{0u};
};

class PSA_Counter : public ExternType {
 public:
  static constexpr unsigned int BYTES = 0;
  static constexpr unsigned int PACKETS = 1;
  static constexpr unsigned int PACKETS_AND_BYTES = 2;

  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(n_counters);
    BM_EXTERN_ATTRIBUTE_ADD(type);
  }

  void init() override;

  P_Counter &get_counter(size_t idx);

  const P_Counter &get_counter(size_t idx) const;

  P_Counter &operator[](size_t idx);

  const P_Counter &operator[](size_t idx) const;

  size_t size() const;

 private:
  Data n_counters;
  Data type;
  std::vector<P_Counter> counters;
};

}  // namespace bm

#endif  // BM_BM_SIM_PSA_COUNTER_H_
