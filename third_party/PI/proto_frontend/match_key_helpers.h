/* Copyright 2019-present Barefoot Networks, Inc.
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

#ifndef SRC_MATCH_KEY_HELPERS_H_
#define SRC_MATCH_KEY_HELPERS_H_

#include <PI/pi.h>

#include "google/rpc/status.pb.h"
#include "p4/v1/p4runtime.pb.h"

#include "common.h"

namespace pi {

class MatchKey;

namespace fe {

namespace proto {

using Status = ::google::rpc::Status;

bool ternary_match_is_dont_care(const p4::v1::FieldMatch::Ternary &mf);

bool range_match_is_dont_care(const p4::v1::FieldMatch::Range &mf);

// This method used to take as parameter a pi_match_key_t pointer instead of a
// pi::MatchKey reference. But all the call sites actually had a pi::MatchKey
// already available so I changed the function. The only potential drawback is
// if no pi::MatchKey object is available and we need to construct one *just* to
// call this function (which would mean memory allocation + copy). We will need
// to re-introduce the other variant if this situation arises.
Status parse_match_key(const pi_p4info_t *p4info, common::p4_id_t table_id,
                       const pi::MatchKey &match_key,
                       p4::v1::TableEntry *entry);

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_MATCH_KEY_HELPERS_H_
