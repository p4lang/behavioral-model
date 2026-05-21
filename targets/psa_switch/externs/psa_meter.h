/*
 * SPDX-FileCopyrightText: 2020 Cornell University
 * Copyright 2020-present Cornell University
 *
 * SPDX-License-Identifier: Apache-2.0
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

  void init() override;

  void execute(const Data &index, Data &value);

  Meter &get_meter(size_t idx);

  const Meter &get_meter(size_t idx) const;

  Meter::MeterErrorCode set_rates(const std::vector<Meter::rate_config_t> &configs);

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
