// SPDX-FileCopyrightText: 2019 Barefoot Networks, Inc.
// Copyright 2019-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include "device_state.h"

#include <bm/bm_sim/switch.h>
#include <PI/p4info.h>

#include <string>

#include "common.h"

namespace pibmv2 {

DeviceState::DeviceState(const pi_p4info_t *p4info) {
  for (auto act_prof_id = pi_p4info_act_prof_begin(p4info);
       act_prof_id != pi_p4info_act_prof_end(p4info);
       act_prof_id = pi_p4info_act_prof_next(p4info, act_prof_id)) {
    auto selector = std::make_shared<GroupSelection>();
    act_prof_selection.emplace(act_prof_id, selector);
    const std::string name(pi_p4info_any_name_from_id(p4info, act_prof_id));
    pibmv2::switch_->set_group_selector(0, name, selector);
  }
}

DeviceLock *device_lock = nullptr;
DeviceState *device_state = nullptr;

}  // namespace pibmv2
