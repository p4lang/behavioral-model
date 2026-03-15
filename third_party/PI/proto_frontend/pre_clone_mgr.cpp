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

#include <limits>

#include "common.h"
#include "pre_clone_mgr.h"
#include "pre_mc_mgr.h"
#include "report_error.h"

namespace p4v1 = ::p4::v1;

namespace pi {

namespace fe {

namespace proto {

using Status = PreCloneMgr::Status;
using CloneSession = PreCloneMgr::CloneSession;
using CloneSessionId = PreCloneMgr::CloneSessionId;
using SessionTemp = common::SessionTemp;

namespace {

PreMcMgr::GroupId
session_id_to_mc_group_id(CloneSessionId session_id) {
  return PreMcMgr::first_reserved_group_id() + session_id;
}

PreMcMgr::GroupEntry
make_mc_group(const CloneSession &clone_session) {
  PreMcMgr::GroupEntry mc_group;
  auto mc_group_id = session_id_to_mc_group_id(clone_session.session_id());
  mc_group.set_multicast_group_id(mc_group_id);
  mc_group.mutable_replicas()->CopyFrom(clone_session.replicas());
  return mc_group;
}

}  // namespace

/* static */ Status
PreCloneMgr::validate_session_id(CloneSessionId session_id) {
  if (session_id < kMinCloneSessionId || session_id >= kMaxCloneSessionId) {
    RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                        "Clone session id out-of-range");
  }
  RETURN_OK_STATUS();
}

/* static */ PreCloneMgr::CloneSessionConfig
PreCloneMgr::make_clone_session_config(
    const CloneSession &clone_session) {
  return CloneSessionConfig{
    clone_session.class_of_service(), clone_session.packet_length_bytes()};
}

PreCloneMgr::PreCloneMgr(pi_dev_tgt_t device_tgt, PreMcMgr* mc_mgr)
    : device_tgt(device_tgt), mc_mgr(mc_mgr) { }

Status
PreCloneMgr::session_set(const CloneSession &clone_session,
                         PreMcMgr::GroupId mc_group_id,
                         const SessionTemp &session) {
  auto session_id = static_cast<CloneSessionId>(clone_session.session_id());
  pi_clone_session_config_t session_config = {};  // value-initialization
  session_config.direction = PI_CLONE_DIRECTION_BOTH;
  session_config.mc_grp_id = mc_group_id;
  session_config.mc_grp_id_valid = true;
  // TODO(antonin): range check?
  session_config.max_packet_length = static_cast<uint16_t>(
      clone_session.packet_length_bytes());

  if (clone_session.class_of_service() != 0) {
    RETURN_ERROR_STATUS(Code::UNIMPLEMENTED,
                        "COS for clone sessions not supported yet");
  }

  auto pi_status = pi_clone_session_set(
      session.get(), device_tgt, session_id, &session_config);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(Code::UNKNOWN,
                        "Error when creating clone session in target");
  }

  RETURN_OK_STATUS();
}

Status
PreCloneMgr::session_create(const CloneSession &clone_session,
                            const SessionTemp &session) {
  auto session_id = static_cast<CloneSessionId>(clone_session.session_id());
  RETURN_IF_ERROR(validate_session_id(session_id));
  Lock lock(mutex);
  if (sessions.count(session_id) > 0) {
    RETURN_ERROR_STATUS(Code::ALREADY_EXISTS,
                        "Clone session id already exists");
  }
  auto mc_group = make_mc_group(clone_session);
  RETURN_IF_ERROR(
      mc_mgr->group_create(mc_group, PreMcMgr::GroupOwner::CLONE_MGR));
  auto status = session_set(
      clone_session, mc_group.multicast_group_id(), session);
  if (IS_OK(status)) {
    sessions.emplace(session_id, make_clone_session_config(clone_session));
    RETURN_OK_STATUS();
  }
  {
    auto status = mc_mgr->group_delete(mc_group);
    if (IS_ERROR(status)) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Clone session set failed and could not undo creation of multicast "
          "group {}. This is a serious error which will prevent you from using "
          "session id {} again until it is resolved",
          mc_group.multicast_group_id(),
          session_id);
    }
  }
  return status;
}

Status
PreCloneMgr::session_modify(const CloneSession &clone_session,
                            const SessionTemp &session) {
  auto session_id = static_cast<CloneSessionId>(clone_session.session_id());
  RETURN_IF_ERROR(validate_session_id(session_id));
  Lock lock(mutex);
  auto it = sessions.find(session_id);
  if (it == sessions.end())
    RETURN_ERROR_STATUS(Code::NOT_FOUND, "Clone session id does not exist");
  auto mc_group = make_mc_group(clone_session);
  RETURN_IF_ERROR(mc_mgr->group_modify(mc_group));

  // update config if needed (e.g. if packet_length_bytes has changed).
  auto new_clone_session_config = make_clone_session_config(clone_session);
  if (new_clone_session_config != it->second) {
    auto status = session_set(
        clone_session, mc_group.multicast_group_id(), session);
    if (IS_OK(status)) {
      it->second = new_clone_session_config;
    }
    return status;
  }

  RETURN_OK_STATUS();
}

Status
PreCloneMgr::session_delete(const CloneSession &clone_session,
                            const SessionTemp &session) {
  auto session_id = static_cast<CloneSessionId>(clone_session.session_id());
  RETURN_IF_ERROR(validate_session_id(session_id));
  Lock lock(mutex);
  auto it = sessions.find(session_id);
  if (it == sessions.end())
    RETURN_ERROR_STATUS(Code::NOT_FOUND, "Clone session id does not exist");
  auto pi_status = pi_clone_session_reset(
      session.get(), device_tgt, session_id);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(Code::UNKNOWN,
                        "Error when resetting clone session in target");
  }
  auto mc_group = make_mc_group(clone_session);
  auto status = mc_mgr->group_delete(mc_group);
  if (IS_OK(status)) {
    sessions.erase(it);
    RETURN_OK_STATUS();
  }
  RETURN_ERROR_STATUS(
      Code::INTERNAL,
      "Clone session was deleted but underlying multicast group {} could not "
      "be deleted. This is a serious error which will prevent you from using "
      "session id {} again until it is resolved",
      mc_group.multicast_group_id(),
      session_id);
}

Status
PreCloneMgr::session_read(const CloneSession &clone_session,
                          const SessionTemp &session,
                          p4v1::ReadResponse *response) const {
  (void) session;
  auto session_id = static_cast<CloneSessionId>(clone_session.session_id());

  auto add_clone_session_to_response = [response, this](
      CloneSessionId session_id, const CloneSessionConfig &clone_session_config)
      -> Status {
    auto *entry = response->add_entities()
      ->mutable_packet_replication_engine_entry()
      ->mutable_clone_session_entry();
    entry->set_session_id(session_id);
    entry->set_class_of_service(clone_session_config.class_of_service);
    entry->set_packet_length_bytes(clone_session_config.packet_length_bytes);
    auto mc_group_id = session_id_to_mc_group_id(session_id);
    PreMcMgr::GroupEntry group_entry;
    auto status = mc_mgr->group_read_one(mc_group_id, &group_entry);
    if (IS_ERROR(status)) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Unexpected error when retrieving replicas list for session id {}",
          session_id);
    }
    entry->mutable_replicas()->CopyFrom(group_entry.replicas());
    RETURN_OK_STATUS();
  };

  Lock lock(mutex);
  if (session_id == 0) {  // wildcard read
    for (const auto &p_session : sessions) {
      RETURN_IF_ERROR(add_clone_session_to_response(
          p_session.first, p_session.second));
    }
  } else {
    auto it = sessions.find(session_id);
    if (it == sessions.end())
      RETURN_ERROR_STATUS(Code::NOT_FOUND, "Clone session id does not exist");
    RETURN_IF_ERROR(add_clone_session_to_response(session_id, it->second));
  }

  RETURN_OK_STATUS();
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
