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

#ifndef SRC_DIRECT_RES_SPEC_H_
#define SRC_DIRECT_RES_SPEC_H_

#include <bm/bm_sim/meters.h>
#include <PI/pi.h>

#include <vector>

namespace pibmv2 {

void convert_from_counter_data(const pi_counter_data_t *from,
                               uint64_t *bytes, uint64_t *packets);

void convert_to_counter_data(pi_counter_data_t *to,
                             uint64_t bytes, uint64_t packets);

std::vector<bm::Meter::rate_config_t> convert_from_meter_spec(
    const pi_meter_spec_t *meter_spec);

void convert_to_meter_spec(const pi_p4info_t *p4info, pi_p4_id_t m_id,
                           pi_meter_spec_t *meter_spec,
                           const std::vector<bm::Meter::rate_config_t> &rates);

}  // namespace pibmv2

#endif  // SRC_DIRECT_RES_SPEC_H_
