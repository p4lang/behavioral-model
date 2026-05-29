/*
 * Copyright 2024 Marvell Technology, Inc.
 * SPDX-FileCopyrightText: 2024 Marvell Technology, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Rupesh Chiluka (rchiluka@marvell.com)
 *
 */

#ifndef PNA_NIC_PNA_METER_H_
#define PNA_NIC_PNA_METER_H_

#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/meters.h>

namespace bm {

namespace pna {

class PNA_Meter : public bm::ExternType {
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

}  // namespace bm::pna

}  // namespace bm
#endif
