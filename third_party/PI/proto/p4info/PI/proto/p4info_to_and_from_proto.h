/* Copyright 2013-present Barefoot Networks, Inc.
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
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef PROTO_P4INFO_PI_PROTO_P4INFO_TO_AND_FROM_PROTO_H_
#define PROTO_P4INFO_PI_PROTO_P4INFO_TO_AND_FROM_PROTO_H_

#include "p4/config/v1/p4info.pb.h"

#include <PI/p4info.h>

namespace pi {

namespace p4info {

p4::config::v1::P4Info p4info_serialize_to_proto(const pi_p4info_t *p4info);

// returns true if success, false otherwise
bool p4info_proto_reader(const p4::config::v1::P4Info &p4info_proto,
                         pi_p4info_t **p4info);

}  // namespace p4info

}  // namespace pi

#endif  // PROTO_P4INFO_PI_PROTO_P4INFO_TO_AND_FROM_PROTO_H_
