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

#ifndef SRC_PRE_MC_MGR_H_
#define SRC_PRE_MC_MGR_H_

#include <PI/pi_base.h>
#include <PI/pi_mc.h>

#include <mutex>
#include <set>
#include <unordered_map>

#include "google/rpc/status.pb.h"
#include "p4/v1/p4runtime.pb.h"

namespace pi {

namespace fe {

namespace proto {

class McSessionTemp;

// Internal representation of a replica port.
struct ReplicaPort {
  p4::v1::Replica::PortKindCase port_kind {};
  pi_mc_port_t port_id {};
  size_t num_bytes {};
};
bool operator==(const ReplicaPort &x, const ReplicaPort &y);
bool operator<(const ReplicaPort &x, const ReplicaPort &y);

// This class is used to map P4Runtime MulticastGroupEntry messages to
// lower-level PI operations. It currently does not do any rollback in case of
// error, which means a single P4Runtime multicast group modification can be
// only partially committed to the target in case of error.
class PreMcMgr {
 public:
  using Status = ::google::rpc::Status;
  using GroupEntry = ::p4::v1::MulticastGroupEntry;
  using GroupId = uint32_t;
  using RId = uint32_t;

  enum class GroupOwner {
    CLIENT,
    CLONE_MGR,
  };

  explicit PreMcMgr(pi_dev_id_t device_id)
      : device_id(device_id) { }

  Status group_create(const GroupEntry &group_entry,
                      GroupOwner owner = GroupOwner::CLIENT);
  Status group_modify(const GroupEntry &group_entry);
  Status group_delete(const GroupEntry &group_entry);
  Status group_read(const GroupEntry &group_entry,
                    ::p4::v1::ReadResponse *response) const;
  Status group_read_one(GroupId group_id, GroupEntry *group_entry) const;

  // user-defined multicast group ids must be in the range
  // ]0,first_reserved_group[; ideally this should be configurable based on the
  // target.
  static constexpr GroupId first_reserved_group_id() { return 1 << 15; }

 private:
  using Mutex = std::mutex;
  using Lock = std::lock_guard<Mutex>;

  struct Node {
    pi_mc_node_handle_t node_h;
    std::set<ReplicaPort> eg_ports{};
  };

  struct Group {
    pi_mc_grp_handle_t group_h;
    std::unordered_map<RId, Node> nodes{};
    GroupOwner owner;
  };

  // cleanup tasks
  struct GroupCleanupTask;
  struct NodeDetachCleanupTask;
  struct NodeCleanupTask;

  Status group_create_(McSessionTemp *session,
                       GroupId group_id,
                       Group *group);
  Status group_modify_(McSessionTemp *session,
                       GroupId group_id,
                       Group *old_group,
                       Group *new_group);

  static Status make_new_group(const GroupEntry &group_entry, Group *group);

  static void read_group(
      GroupId group_id, const Group &group, GroupEntry *group_entry);

  Status create_and_attach_node(McSessionTemp *session,
                                pi_mc_grp_handle_t group_h,
                                RId rid,
                                Node *node);
  Status modify_node(const McSessionTemp &session, const Node &node);
  Status detach_and_delete_node(const McSessionTemp &session,
                                pi_mc_grp_handle_t group_h,
                                const Node &node);

  pi_dev_id_t device_id;
  std::unordered_map<GroupId, Group> groups{};
  mutable Mutex mutex{};
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_PRE_MC_MGR_H_
