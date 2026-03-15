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

#ifndef SRC_WATCH_PORT_ENFORCER_H_
#define SRC_WATCH_PORT_ENFORCER_H_

#include <PI/pi_base.h>

#include <chrono>
#include <memory>
#include <set>
#include <thread>
#include <unordered_map>

#include "common.h"

namespace pi {

class ActProf;

namespace fe {

namespace proto {

class AccessArbitration;

template <typename Clock> class TaskQueue;
using WatchPortTaskQueue = TaskQueue<std::chrono::steady_clock>;

// Receives port notifications from PI and activate / deactivate group members
// as needed (based on their watch port attribute). We use an asynchronous task
// queue to process port status events, to guarantee that the PI port status
// event callback never "blocks" for too long.
class WatchPortEnforcer {
 public:
  static constexpr pi_port_t INVALID_WATCH = -1;

  WatchPortEnforcer(pi_dev_tgt_t device_tgt,
                    AccessArbitration *access_arbitration);
  ~WatchPortEnforcer();

  // all the public methods of WatchPortEnforcer assume that the caller has
  // write access to the action profile; these methods are synchronous and not
  // executed by the task_queue_thread.

  // add_member and modify_member update the internal state of the
  // WatchPortEnforcer but do not do any PI calls, unlike the *_update_hw
  // versions, which call pi_act_prof_grp_activate_mbr and
  // pi_act_prof_grp_deactivate_mbr as appropriate.

  Status add_member(pi_p4_id_t action_prof_id,
                    pi_indirect_handle_t grp_h,
                    pi_indirect_handle_t mbr_h,
                    pi_port_t new_watch);

  Status modify_member(pi_p4_id_t action_prof_id,
                       pi_indirect_handle_t grp_h,
                       pi_indirect_handle_t mbr_h,
                       pi_port_t current_watch,
                       pi_port_t new_watch);

  // does not update HW, so really should not fail unless inconsistent state at
  // the caller.
  Status delete_member(pi_p4_id_t action_prof_id,
                       pi_indirect_handle_t grp_h,
                       pi_indirect_handle_t mbr_h,
                       pi_port_t current_watch);

  // If new_watch is DOWN, will call pi_act_prof_grp_deactivate_mbr
  Status add_member_and_update_hw(pi::ActProf *ap,
                                  pi_indirect_handle_t grp_h,
                                  pi_indirect_handle_t mbr_h,
                                  pi_port_t new_watch);

  // Call pi_act_prof_grp_activate_mbr / pi_act_prof_grp_deactivate_mbr as
  // needed
  Status modify_member_and_update_hw(pi::ActProf *ap,
                                     pi_indirect_handle_t grp_h,
                                     pi_indirect_handle_t mbr_h,
                                     pi_port_t current_watch,
                                     pi_port_t new_watch);

  pi_port_status_t get_port_status(pi_p4_id_t action_prof_id,
                                   pi_port_t watch);

  // Blocks until task queue has processed the p4info change.
  Status p4_change(const pi_p4info_t *p4info);

  // Add port status to task queue and block until is has been processed.
  void handle_port_status_event_sync(pi_port_t port, pi_port_status_t status);

  WatchPortEnforcer(const WatchPortEnforcer &) = delete;
  WatchPortEnforcer &operator=(const WatchPortEnforcer &) = delete;
  WatchPortEnforcer(WatchPortEnforcer &&) = delete;
  WatchPortEnforcer &operator=(WatchPortEnforcer &&) = delete;

 private:
  static void port_status_event_cb(pi_dev_id_t dev_id, pi_port_t port,
                                   pi_port_status_t status, void *cookie);

  void handle_port_status_event_async(pi_port_t port, pi_port_status_t status);

  void set_port_status(pi_port_t port, pi_port_status_t status);

  Status activate_member(pi::ActProf *ap,
                         pi_indirect_handle_t grp_h,
                         pi_indirect_handle_t mbr_h);

  Status deactivate_member(pi::ActProf *ap,
                           pi_indirect_handle_t grp_h,
                           pi_indirect_handle_t mbr_h);

  void update_ports_status_cache(pi_port_t port);

  struct Member {
    pi_indirect_handle_t grp_h;
    pi_indirect_handle_t mbr_h;
  };

  struct MemberCmp {
    bool operator()(const Member &mbr1, const Member &mbr2) const {
      if (mbr1.grp_h < mbr2.grp_h) return true;
      return (mbr1.grp_h < mbr2.grp_h) ||
          (mbr1.grp_h == mbr2.grp_h && mbr1.mbr_h < mbr2.mbr_h);
    }
  };

  struct MembersForPort {
    std::set<Member, MemberCmp> members;
  };

  class PortStatus {
   public:
    PortStatus()
        : status(PI_PORT_STATUS_DOWN) { }
    PortStatus(pi_port_status_t status)  // NOLINT(runtime/explicit)
        : status(status) { }

    operator pi_port_status_t() const {
      return status;
    }

   private:
    pi_port_status_t status;
  };

  struct MembersForActionProf {
    // each action profile has its own port status map, we guarantee consistency
    // between a port oper status and a member activation status.
    std::unordered_map<pi_port_t, PortStatus> ports_status;
    std::unordered_map<pi_port_t, MembersForPort> members_by_port;
  };

  pi_dev_tgt_t device_tgt;
  const pi_p4info_t *p4info{nullptr};
  std::unique_ptr<WatchPortTaskQueue> task_queue;
  std::unordered_map<common::p4_id_t, MembersForActionProf>
  members_by_action_prof;
  // "lazy cache" of the oper status for each port; in case of P4 change (when
  // we clear the members_by_action_prof map, we use this cache to avoid
  // querying the state of every port again.
  std::unordered_map<pi_port_t, PortStatus> ports_status_cache;
  std::thread task_queue_thread;
  AccessArbitration *access_arbitration;
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_WATCH_PORT_ENFORCER_H_
