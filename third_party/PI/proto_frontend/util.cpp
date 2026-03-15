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

#include <PI/proto/util.h>

namespace pi {

namespace proto {

namespace util {

p4::config::v1::P4Ids::Prefix
resource_type_from_id(p4_id_t p4_id) {
  using p4::config::v1::P4Ids;
  switch (p4_id >> 24) {
    case static_cast<p4_id_t>(P4Ids::UNSPECIFIED):
      return P4Ids::UNSPECIFIED;
    case static_cast<p4_id_t>(P4Ids::ACTION):
      return P4Ids::ACTION;
    case static_cast<p4_id_t>(P4Ids::TABLE):
      return P4Ids::TABLE;
    case static_cast<p4_id_t>(P4Ids::VALUE_SET):
      return P4Ids::VALUE_SET;
    case static_cast<p4_id_t>(P4Ids::ACTION_PROFILE):
      return P4Ids::ACTION_PROFILE;
    case static_cast<p4_id_t>(P4Ids::COUNTER):
      return P4Ids::COUNTER;
    case static_cast<p4_id_t>(P4Ids::DIRECT_COUNTER):
      return P4Ids::DIRECT_COUNTER;
    case static_cast<p4_id_t>(P4Ids::METER):
      return P4Ids::METER;
    case static_cast<p4_id_t>(P4Ids::DIRECT_METER):
      return P4Ids::DIRECT_METER;
    default:
      return P4Ids::UNSPECIFIED;
  }
}

}  // namespace util

}  // namespace proto

}  // namespace pi
