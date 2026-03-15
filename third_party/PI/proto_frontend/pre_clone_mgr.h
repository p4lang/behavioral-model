/* Copyright 2018-present Barefoot Networks, Inc.
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

#ifndef SRC_PRE_CLONE_MGR_H_
#define SRC_PRE_CLONE_MGR_H_

#include <PI/pi_base.h>
#include <PI/pi_clone.h>

#include <mutex>
#include <unordered_map>

#include "google/rpc/status.pb.h"
#include "p4/v1/p4runtime.pb.h"

#include "pre_mc_mgr.h"

namespace pi {

namespace fe {

namespace proto {

namespace common { class SessionTemp; }  // namespace common

// This class is used to map P4Runtime CloneSessionEntry messages to lower-level
// PI operations. At the moment every clone session is associated to a multicast
// group.
class PreCloneMgr {
 public:
  using Status = ::google::rpc::Status;
  using CloneSession = ::p4::v1::CloneSessionEntry;
  using CloneSessionId = uint32_t;
  using SessionTemp = common::SessionTemp;

  PreCloneMgr(pi_dev_tgt_t device_tgt, PreMcMgr* mc_mgr);

  Status session_create(const CloneSession &clone_session,
                        const SessionTemp &session);
  Status session_modify(const CloneSession &clone_session,
                        const SessionTemp &session);
  Status session_delete(const CloneSession &clone_session,
                        const SessionTemp &session);
  Status session_read(const CloneSession &clone_session,
                      const SessionTemp &session,
                      ::p4::v1::ReadResponse *response) const;

 private:
  using Mutex = std::mutex;
  using Lock = std::lock_guard<Mutex>;

  struct CloneSessionConfig {
    uint32_t class_of_service;
    int32_t packet_length_bytes;

    bool operator==(const CloneSessionConfig &other) const {
      return class_of_service == other.class_of_service &&
          packet_length_bytes == other.packet_length_bytes;
    }

    bool operator!=(const CloneSessionConfig &other) const {
      return !(*this == other);
    }
  };

  // We set the max session ID value to 32768.
  // This is the the max value supported by simple_switch, which reserves the
  // left-most bit
  // https://github.com/p4lang/behavioral-model/blob/
  // e9fa7dc687f334e5cf327e0c993fc1a351d224c0/targets/simple_switch/register_access.h#L46
  // Additionally, for clone sessions to more than 1 port, PI will program a
  // multicast group. There may only be 32768 mgids available for this usage
  // (with another 32768 reserved for user-defined multicast groups).
  // TODO(antonin): Ideally, these values should be configurable based on the
  // target. Other targets may support a different number of clone sessions.
  static constexpr CloneSessionId kMinCloneSessionId = 1;
  static constexpr CloneSessionId kMaxCloneSessionId = 32768;

  Status session_set(const CloneSession &clone_session,
                     PreMcMgr::GroupId mc_group_id,
                     const SessionTemp &session);

  static Status validate_session_id(CloneSessionId session_id);

  static CloneSessionConfig make_clone_session_config(
      const CloneSession &clone_session);

  pi_dev_tgt_t device_tgt;
  PreMcMgr* mc_mgr;  // non-owning pointer
  std::unordered_map<CloneSessionId, CloneSessionConfig> sessions{};
  mutable Mutex mutex{};
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_PRE_CLONE_MGR_H_
