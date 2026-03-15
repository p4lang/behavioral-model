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

#ifndef PI_PROTO_UTIL_H_
#define PI_PROTO_UTIL_H_

#include <cstdint>

#include "p4/config/v1/p4info.pb.h"

namespace pi {

namespace proto {

namespace util {

using p4_id_t = uint32_t;

constexpr p4_id_t invalid_id() { return 0; }

p4::config::v1::P4Ids::Prefix resource_type_from_id(p4_id_t p4_id);

}  // namespace util

}  // namespace proto

}  // namespace pi

#endif  // PI_PROTO_UTIL_H_
