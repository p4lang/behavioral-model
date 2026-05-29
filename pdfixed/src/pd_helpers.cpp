// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/pdfixed/int/pd_helpers.h>
#include <bm/pdfixed/int/pd_conn_mgr.h>

#include <vector>

std::vector<BmMeterRateConfig>
pd_bytes_meter_spec_to_rates(p4_pd_bytes_meter_spec_t *meter_spec) {
  double info_rate;
  uint32_t burst_size;
  BmMeterRateConfig rate;

  std::vector<BmMeterRateConfig> rates;

  // bytes per microsecond
  info_rate = static_cast<double>(meter_spec->cir_kbps) / 8000.;
  burst_size = meter_spec->cburst_kbits * 1000 / 8;
  rate.units_per_micros = info_rate; rate.burst_size = burst_size;
  rates.push_back(rate);

  info_rate = static_cast<double>(meter_spec->pir_kbps) / 8000.;
  burst_size = meter_spec->pburst_kbits * 1000 / 8;
  rate.units_per_micros = info_rate; rate.burst_size = burst_size;
  rates.push_back(rate);

  return rates;
}

std::vector<BmMeterRateConfig>
pd_packets_meter_spec_to_rates(p4_pd_packets_meter_spec_t *meter_spec) {
  double info_rate;
  uint32_t burst_size;
  BmMeterRateConfig rate;

  std::vector<BmMeterRateConfig> rates;

  info_rate = static_cast<double>(meter_spec->cir_pps) / 1000000.;
  burst_size = meter_spec->cburst_pkts;
  rate.units_per_micros = info_rate; rate.burst_size = burst_size;
  rates.push_back(rate);

  info_rate = static_cast<double>(meter_spec->pir_pps) / 1000000.;
  burst_size = meter_spec->pburst_pkts;
  rate.units_per_micros = info_rate; rate.burst_size = burst_size;
  rates.push_back(rate);

  return rates;
}
