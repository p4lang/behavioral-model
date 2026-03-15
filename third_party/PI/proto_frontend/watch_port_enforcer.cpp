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

#include "watch_port_enforcer.h"

#include <PI/frontends/cpp/tables.h>
#include <PI/pi_base.h>

#include <future>
#include <memory>
#include <thread>
#include <utility>  // std::move

#include "access_arbitration.h"
#include "common.h"
#include "logger.h"
#include "report_error.h"
#include "task_queue.h"

namespace pi {

namespace fe {

namespace proto {

namespace {

using EmptyPromise = std::promise<void>;

}  // namespace

/* static */
constexpr pi_port_t WatchPortEnforcer::INVALID_WATCH;

Status
WatchPortEnforcer::activate_member(pi::ActProf *ap,
                                   pi_indirect_handle_t grp_h,
                                   pi_indirect_handle_t mbr_h) {
  Logger::get()->debug(
      "Activating member {} in group {} in action profile {}",
      mbr_h, grp_h, ap->get_id());
  auto pi_status = ap->group_activate_member(grp_h, mbr_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::INTERNAL,
        "WatchPortEnforcer: error when activating member {} "
        "in group {} in action profile {}",
        mbr_h, grp_h, ap->get_id());
  }
  RETURN_OK_STATUS();
}

Status
WatchPortEnforcer::deactivate_member(pi::ActProf *ap,
                                     pi_indirect_handle_t grp_h,
                                     pi_indirect_handle_t mbr_h) {
  Logger::get()->debug(
      "Deactivating member {} in group {} in action profile {}",
      mbr_h, grp_h, ap->get_id());
  auto pi_status = ap->group_deactivate_member(grp_h, mbr_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::INTERNAL,
        "WatchPortEnforcer: error when deactivating member {} "
        "in group {} in action profile {}",
        mbr_h, grp_h, ap->get_id());
  }
  RETURN_OK_STATUS();
}

WatchPortEnforcer::WatchPortEnforcer(pi_dev_tgt_t device_tgt,
                                     AccessArbitration *access_arbitration)
    : device_tgt(device_tgt),
      task_queue(new WatchPortTaskQueue()),
      access_arbitration(access_arbitration) {
  task_queue_thread = std::thread(
      &WatchPortTaskQueue::execute, task_queue.get());
  pi_port_status_register_cb(device_tgt.dev_id,
                             &WatchPortEnforcer::port_status_event_cb,
                             static_cast<void *>(this));
}

WatchPortEnforcer::~WatchPortEnforcer() {
  task_queue->stop();
  task_queue_thread.join();
}

Status
WatchPortEnforcer::p4_change(const pi_p4info_t *p4info) {
  class TaskP4Change : public TaskIface {
   public:
    TaskP4Change(WatchPortEnforcer *enforcer,
                 const pi_p4info_t *p4info,
                 EmptyPromise &promise)  // NOLINT(runtime/references)
        : enforcer(enforcer), p4info(p4info), promise(promise) { }

    void operator()() override {
      enforcer->p4info = p4info;

      auto &members_by_action_prof = enforcer->members_by_action_prof;
      members_by_action_prof.clear();
      for (auto action_prof_id = pi_p4info_act_prof_begin(p4info);
           action_prof_id != pi_p4info_act_prof_end(p4info);
           action_prof_id = pi_p4info_act_prof_next(p4info, action_prof_id)) {
        MembersForActionProf v;
        v.ports_status = enforcer->ports_status_cache;
        members_by_action_prof.emplace(action_prof_id, std::move(v));
      }

      promise.set_value();
    }

   private:
    WatchPortEnforcer *enforcer;
    const pi_p4info_t *p4info;
    EmptyPromise &promise;
  };

  EmptyPromise promise;
  task_queue->execute_task(std::unique_ptr<TaskIface>(
      new TaskP4Change(this, p4info, promise)));
  promise.get_future().wait();
  RETURN_OK_STATUS();
}

void
WatchPortEnforcer::set_port_status(pi_port_t port, pi_port_status_t status) {
  ports_status_cache[port] = status;

  AccessArbitration::P4IdSet act_prof_ids;
  for (auto &p : members_by_action_prof) act_prof_ids.insert(p.first);

  while (!act_prof_ids.empty()) {
    // prevent simultaneous writes (by the P4Runtime client) while we update the
    // status of each member
    // if there is an ongoing pipeline configuration update, we do not perform
    // any activate / deactivate operation, waiting for the lock would put us in
    // a potential deadlock situation
    // we use "one_of" to get access to an available action profile (which is
    // not locked for a WriteRequest) instead of getting access to the action
    // profiles in some arbitrary order; this ensures that we do not get blocked
    // by an ongoing WriteRequest and we can update member status in a timely
    // fashion for available action profiles.
    AccessArbitration::NoWriteAccess access(
        access_arbitration, &act_prof_ids,
        AccessArbitration::one_of, AccessArbitration::skip_if_update);
    if (!access) break;
    auto &action_prof = members_by_action_prof.at(access.p4_id());

    auto &current_status = action_prof.ports_status[port];

    if (current_status == status) {
      Logger::get()->info(
          "WatchPortEnforcer {}: port status hasn't changed, "
          "ignoring notification", access.p4_id());
      return;
    }

    current_status = status;
    auto &members_for_port = action_prof.members_by_port[port];
    if (members_for_port.members.empty()) continue;

    // Maybe the decision to enable / disable batching for members activate /
    // deactivate should be made on a per-target basis. Something for which we
    // can consider having a configuration parameter exposed in a configuration
    // file.
    common::SessionTemp session(false  /* = batch */);
    pi::ActProf ap(session.get(), device_tgt, p4info, access.p4_id());
    if (status == PI_PORT_STATUS_UP) {
      for (auto member : members_for_port.members) {
        activate_member(&ap, member.grp_h, member.mbr_h);
      }
    } else if (status == PI_PORT_STATUS_DOWN) {
      for (auto member : members_for_port.members) {
        deactivate_member(&ap, member.grp_h, member.mbr_h);
      }
    } else {
      Logger::get()->error("WatchPortEnforcer: unknown port status %d in notification", static_cast<int>(status));
    }
  }
}

void
WatchPortEnforcer::handle_port_status_event_async(pi_port_t port,
                                                  pi_port_status_t status) {
  class TaskPortEvent : public TaskIface {
   public:
    TaskPortEvent(WatchPortEnforcer *enforcer,
                  pi_port_t port,
                  pi_port_status_t status)
        : enforcer(enforcer), port(port), status(status) { }

    void operator()() override {
      enforcer->set_port_status(port, status);
    }

   private:
    WatchPortEnforcer *enforcer;
    pi_port_t port;
    pi_port_status_t status;
  };

  task_queue->execute_task(std::unique_ptr<TaskIface>(
      new TaskPortEvent(this, port, status)));
}

void
WatchPortEnforcer::handle_port_status_event_sync(pi_port_t port,
                                                 pi_port_status_t status) {
  class TaskPortEvent : public TaskIface {
   public:
    TaskPortEvent(WatchPortEnforcer *enforcer,
                  pi_port_t port,
                  pi_port_status_t status,
                  EmptyPromise &promise)  // NOLINT(runtime/references)
        : enforcer(enforcer), port(port), status(status), promise(promise) { }

    void operator()() override {
      enforcer->set_port_status(port, status);
      promise.set_value();
    }

   private:
    WatchPortEnforcer *enforcer;
    pi_port_t port;
    pi_port_status_t status;
    EmptyPromise &promise;
  };

  EmptyPromise promise;
  task_queue->execute_task(std::unique_ptr<TaskIface>(
      new TaskPortEvent(this, port, status, promise)));
  promise.get_future().wait();
}

Status
WatchPortEnforcer::add_member(pi_p4_id_t action_prof_id,
                              pi_indirect_handle_t grp_h,
                              pi_indirect_handle_t mbr_h,
                              pi_port_t new_watch) {
  if (new_watch == INVALID_WATCH) RETURN_OK_STATUS();

  auto &members_by_port =
      members_by_action_prof.at(action_prof_id).members_by_port;

  auto p = members_by_port[new_watch].members.insert(Member{grp_h, mbr_h});
  if (!p.second) {
    RETURN_ERROR_STATUS(
        Code::INTERNAL, "Member is already in member list for watch port");
  }

  RETURN_OK_STATUS();
}

Status
WatchPortEnforcer::add_member_and_update_hw(pi::ActProf *ap,
                                            pi_indirect_handle_t grp_h,
                                            pi_indirect_handle_t mbr_h,
                                            pi_port_t new_watch) {
  if (new_watch == INVALID_WATCH) RETURN_OK_STATUS();

  RETURN_IF_ERROR(add_member(ap->get_id(), grp_h, mbr_h, new_watch));

  auto new_status = get_port_status(ap->get_id(), new_watch);
  if (new_status == PI_PORT_STATUS_DOWN) {
    RETURN_IF_ERROR(deactivate_member(ap, grp_h, mbr_h));
  }

  RETURN_OK_STATUS();
}

Status
WatchPortEnforcer::modify_member(pi_p4_id_t action_prof_id,
                                 pi_indirect_handle_t grp_h,
                                 pi_indirect_handle_t mbr_h,
                                 pi_port_t current_watch,
                                 pi_port_t new_watch) {
  if (current_watch == INVALID_WATCH && new_watch == INVALID_WATCH)
    RETURN_OK_STATUS();

  if (current_watch == new_watch)
    RETURN_OK_STATUS();

  auto &members_by_port =
      members_by_action_prof.at(action_prof_id).members_by_port;

  if (current_watch != INVALID_WATCH) {
    auto c = members_by_port[current_watch].members.erase(Member{grp_h, mbr_h});
    if (c == 0) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL, "Cannot find member in member list for watch port");
    }
  }

  if (new_watch != INVALID_WATCH) {
    auto p = members_by_port[new_watch].members.insert(Member{grp_h, mbr_h});
    if (!p.second) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL, "Member is already in member list for watch port");
    }
  }

  RETURN_OK_STATUS();
}

Status
WatchPortEnforcer::modify_member_and_update_hw(pi::ActProf *ap,
                                               pi_indirect_handle_t grp_h,
                                               pi_indirect_handle_t mbr_h,
                                               pi_port_t current_watch,
                                               pi_port_t new_watch) {
  if (current_watch == INVALID_WATCH && new_watch == INVALID_WATCH)
    RETURN_OK_STATUS();

  if (current_watch == new_watch)
    RETURN_OK_STATUS();

  RETURN_IF_ERROR(
      modify_member(ap->get_id(), grp_h, mbr_h, current_watch, new_watch));

  auto current_status = get_port_status(ap->get_id(), current_watch);
  auto new_status = get_port_status(ap->get_id(), new_watch);

  if (current_watch == INVALID_WATCH) {
    if (new_status == PI_PORT_STATUS_UP) {
      RETURN_IF_ERROR(activate_member(ap, grp_h, mbr_h));
    } else {
      RETURN_IF_ERROR(deactivate_member(ap, grp_h, mbr_h));
    }
  } else if (new_watch == INVALID_WATCH) {
    if (current_status == PI_PORT_STATUS_DOWN) {
      RETURN_IF_ERROR(activate_member(ap, grp_h, mbr_h));
    }
  } else {
    if (current_status != new_status) {
      if (new_status == PI_PORT_STATUS_UP) {
        RETURN_IF_ERROR(activate_member(ap, grp_h, mbr_h));
      } else {
        RETURN_IF_ERROR(deactivate_member(ap, grp_h, mbr_h));
      }
    }
  }

  RETURN_OK_STATUS();
}

Status
WatchPortEnforcer::delete_member(pi_p4_id_t action_prof_id,
                                 pi_indirect_handle_t grp_h,
                                 pi_indirect_handle_t mbr_h,
                                 pi_port_t current_watch) {
  if (current_watch == INVALID_WATCH) RETURN_OK_STATUS();

  auto &members_by_port =
      members_by_action_prof.at(action_prof_id).members_by_port;

  auto c = members_by_port[current_watch].members.erase(Member{grp_h, mbr_h});
  if (c == 0) {
    RETURN_ERROR_STATUS(
        Code::INTERNAL, "Cannot find member in member list for watch port");
  }

  RETURN_OK_STATUS();
}

pi_port_status_t
WatchPortEnforcer::get_port_status(pi_p4_id_t action_prof_id, pi_port_t watch) {
  if (watch == INVALID_WATCH) return PI_PORT_STATUS_UP;
  auto &ports_status = members_by_action_prof.at(action_prof_id).ports_status;
  auto it = ports_status.find(watch);
  if (it != ports_status.end()) return it->second;
  pi_port_status_t status;
  auto pi_status = pi_port_status_get(device_tgt.dev_id, watch, &status);
  if (pi_status == PI_STATUS_SUCCESS) {
    ports_status[watch] = status;
    update_ports_status_cache(watch);
    return status;
  }
  return PI_PORT_STATUS_DOWN;
}

void
WatchPortEnforcer::update_ports_status_cache(pi_port_t port) {
  class UpdateCache : public TaskIface {
   public:
    UpdateCache(WatchPortEnforcer *enforcer, pi_port_t port)
        : enforcer(enforcer), port(port) { }

    void operator()() override {
      auto &cache = enforcer->ports_status_cache;
      pi_port_status_t status;
      auto pi_status = pi_port_status_get(
          enforcer->device_tgt.dev_id, port, &status);
      if (pi_status != PI_STATUS_SUCCESS) return;
      cache[port] = status;
    }

   private:
    WatchPortEnforcer *enforcer;
    pi_port_t port;
  };

  task_queue->execute_task(std::unique_ptr<TaskIface>(
      new UpdateCache(this, port)));
}

/* static */
void
WatchPortEnforcer::port_status_event_cb(pi_dev_id_t dev_id,
                                        pi_port_t port,
                                        pi_port_status_t status,
                                        void *cookie) {
  (void)dev_id;
  auto *enforcer = static_cast<WatchPortEnforcer *>(cookie);
  assert(dev_id == enforcer->device_tgt.dev_id);
  enforcer->handle_port_status_event_async(port, status);
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
