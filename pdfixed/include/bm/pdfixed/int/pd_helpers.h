/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef BM_PDFIXED_INT_PD_HELPERS_H_
#define BM_PDFIXED_INT_PD_HELPERS_H_

#include <bm/Standard.h>

#include <bm/pdfixed/pd_common.h>

#include <vector>

using ::bm_runtime::standard::BmMeterRateConfig;

std::vector<BmMeterRateConfig>
pd_bytes_meter_spec_to_rates(p4_pd_bytes_meter_spec_t *meter_spec);

std::vector<BmMeterRateConfig>
pd_packets_meter_spec_to_rates(p4_pd_packets_meter_spec_t *meter_spec);

#endif  // BM_PDFIXED_INT_PD_HELPERS_H_
