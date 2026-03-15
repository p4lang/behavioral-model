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

#ifndef SRC_ACTION_HELPERS_H_
#define SRC_ACTION_HELPERS_H_

#include <PI/pi.h>
#include <PI/frontends/cpp/tables.h>

#include "google/rpc/status.pb.h"
#include "p4/v1/p4runtime.pb.h"

namespace pi {

namespace fe {

namespace proto {

using Status = ::google::rpc::Status;

Status construct_action_data(const pi_p4info_t *p4info,
                             const p4::v1::Action &action,
                             pi::ActionData *action_data);

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_ACTION_HELPERS_H_
