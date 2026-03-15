/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
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
 * Antonin Bas
 *
 */

#include "action_helpers.h"

#include <PI/frontends/cpp/tables.h>

#include "google/rpc/code.pb.h"
#include "google/rpc/status.pb.h"
#include "p4/v1/p4runtime.pb.h"

#include "common.h"
#include "report_error.h"
#include "status_macros.h"

namespace p4v1 = ::p4::v1;

namespace pi {

namespace fe {

namespace proto {

using common::bytestring_p4rt_to_pi;

Status construct_action_data(const pi_p4info_t *p4info,
                             const p4v1::Action &action,
                             pi::ActionData *action_data) {
  size_t exp_num_params = pi_p4info_action_num_params(
      p4info, action.action_id());
  if (static_cast<size_t>(action.params().size()) != exp_num_params) {
    RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                        "Unexpected number of action parameters");
  }
  for (const auto &p : action.params()) {
    auto not_found = static_cast<size_t>(-1);
    size_t bitwidth = pi_p4info_action_param_bitwidth(
        p4info, action.action_id(), p.param_id());
    if (bitwidth == not_found) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Unknown action parameter");
    }
    ASSIGN_OR_RETURN(auto value, bytestring_p4rt_to_pi(p.value(), bitwidth));
    action_data->set_arg(p.param_id(), value.data(), value.size());
  }
  RETURN_OK_STATUS();
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
