/* Copyright 2020-present Cornell University
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
 * Yunhe Liu (yunheliu@cs.cornell.edu)
 *
 */

#ifndef PSA_SWITCH_PSA_METER_H_
#define PSA_SWITCH_PSA_METER_H_

#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/meters.h>

namespace bm {

namespace psa {

class PSA_Meter : public bm::ExternType {
 public:
  static constexpr p4object_id_t spec_id = 0xfffffffe;

  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(n_meters);
    BM_EXTERN_ATTRIBUTE_ADD(type);
    BM_EXTERN_ATTRIBUTE_ADD(is_direct);
    BM_EXTERN_ATTRIBUTE_ADD(rate_count);
  }
  
  void init() override {
    bm::MeterArray::MeterType meter_type;
    if (type == "bytes") {
        meter_type = bm::MeterArray::MeterType::BYTES;
    } else if (type == "packets") {
        meter_type = bm::MeterArray::MeterType::PACKETS;
    } else {
        // TODO: error reporting
    }
    _meter = std::unique_ptr<MeterArray>(
        new MeterArray(get_name() + ".$impl",
                         spec_id,
                         meter_type,
                         rate_count.get<size_t>(),
                         n_meters.get<size_t>()));

        // Default trTriColor meter rates
        // 2 packets per second, burst size of 3
        Meter::rate_config_t committed_rate = {0.000002, 3};
        // 10 packets per second, burst size of 1
        Meter::rate_config_t peak_rate = {0.00001, 1};
        Meter::MeterErrorCode error = _meter->set_rates({committed_rate, peak_rate});
        // TODO return error handling
  }

  void execute(const Data &index, Data &value);

  Meter &get_Meter(size_t idx);

  const Meter &get_Meter(size_t idx) const;

  size_t size() const { return _meter->size(); };

 private:
  Data n_meters;
  std::string type;
  Data is_direct;
  Data rate_count;
  Data color;
  std::unique_ptr<MeterArray> _meter;
};

}  // namespace bm::psa

}  // namespace bm
#endif
