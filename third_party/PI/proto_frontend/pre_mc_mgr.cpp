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

#include <PI/pi_mc.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <utility>  // for std::move
#include <tuple>
#include <vector>

#include "google/rpc/code.pb.h"

#include "common.h"
#include "pre_mc_mgr.h"
#include "report_error.h"
#include "p4/v1/p4runtime.pb.h"

namespace p4v1 = ::p4::v1;

namespace pi {

namespace fe {

namespace proto {

using Code = ::google::rpc::Code;
using Status = PreMcMgr::Status;
using GroupEntry = PreMcMgr::GroupEntry;

std::tuple<p4v1::Replica::PortKindCase, pi_mc_port_t, size_t>
ReplicaPortAsTuple(const ReplicaPort &port) {
  return std::make_tuple(port.port_kind, port.port_id, port.num_bytes);
}
bool operator==(const ReplicaPort &x, const ReplicaPort &y) {
  return ReplicaPortAsTuple(x) == ReplicaPortAsTuple(y);
}
bool operator<(const ReplicaPort &x, const ReplicaPort &y) {
  return ReplicaPortAsTuple(x) < ReplicaPortAsTuple(y);
}

struct McLocalCleanupIface {
  virtual ~McLocalCleanupIface() { }

  virtual Status cleanup(const McSessionTemp &session) = 0;
  virtual void cancel() = 0;
};

class McSessionTemp final
    : public common::SessionCleanup<McSessionTemp, McLocalCleanupIface> {
 public:
  McSessionTemp() {
    pi_mc_session_init(&sess);
  }

  ~McSessionTemp() {
    pi_mc_session_cleanup(sess);
  }

  pi_mc_session_handle_t get() const { return sess; }

 private:
  pi_mc_session_handle_t sess;
};

struct PreMcMgr::GroupCleanupTask : public McLocalCleanupIface {
  GroupCleanupTask(PreMcMgr *pre_mgr, pi_mc_grp_handle_t group_h)
      : pre_mgr(pre_mgr), group_h(group_h) { }

  Status cleanup(const McSessionTemp &session) override {
    if (!pre_mgr) RETURN_OK_STATUS();
    auto pi_status = pi_mc_grp_delete(
        session.get(), pre_mgr->device_id, group_h);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Error encountered when cleaning up multicast group. "
          "This is a serious error and there may be a dangling group. "
          "You may need to reboot the system");
    }
    RETURN_OK_STATUS();
  }

  void cancel() override {
    pre_mgr = nullptr;
  }

  PreMcMgr *pre_mgr;
  pi_mc_grp_handle_t group_h;
};

struct PreMcMgr::NodeDetachCleanupTask : public McLocalCleanupIface {
  NodeDetachCleanupTask(PreMcMgr *pre_mgr,
                        pi_mc_grp_handle_t group_h,
                        pi_mc_node_handle_t node_h)
      : pre_mgr(pre_mgr), group_h(group_h), node_h(node_h) { }

  Status cleanup(const McSessionTemp &session) override {
    if (!pre_mgr) RETURN_OK_STATUS();
    auto pi_status = pi_mc_grp_detach_node(
        session.get(), pre_mgr->device_id, group_h, node_h);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Error encountered when detaching multicast node from group. "
          "This is a serious error that should definitely not happen. "
          "You may need to reboot the system");
    }
    RETURN_OK_STATUS();
  }

  void cancel() override {
    pre_mgr = nullptr;
  }

  PreMcMgr *pre_mgr;
  pi_mc_grp_handle_t group_h;
  pi_mc_node_handle_t node_h;
};

struct PreMcMgr::NodeCleanupTask : public McLocalCleanupIface {
  NodeCleanupTask(PreMcMgr *pre_mgr, pi_mc_node_handle_t node_h)
      : pre_mgr(pre_mgr), node_h(node_h) { }

  Status cleanup(const McSessionTemp &session) override {
    if (!pre_mgr) RETURN_OK_STATUS();
    auto pi_status = pi_mc_node_delete(
        session.get(), pre_mgr->device_id, node_h);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Error encountered when deleting multicast node from group. "
          "This is a serious error and there may be a dangling node. "
          "You may need to reboot the system");
    }
    RETURN_OK_STATUS();
  }

  void cancel() override {
    pre_mgr = nullptr;
  }

  PreMcMgr *pre_mgr;
  pi_mc_node_handle_t node_h;
};

namespace {

// Extracts the egress port of a given P4Runtime `replica` into the given
// `ReplicaPort`.
Status GetReplicaPort(const p4v1::Replica &replica, ReplicaPort *egress_port) {
  egress_port->port_kind = replica.port_kind_case();
  switch (replica.port_kind_case()) {
    case p4v1::Replica::kEgressPort: {
      egress_port->port_id = static_cast<pi_mc_port_t>(replica.egress_port());
      RETURN_OK_STATUS();
    }
    case p4v1::Replica::kPort: {
      egress_port->num_bytes = replica.port().size();
      return common::bytestring_to_pi_port(replica.port(),
                                           &egress_port->port_id);
    }
    default:
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Missing port in multicast group replica");
  }
}

// Sets the `port_kind` oneof of the given `replica` to the given `port`.
Status SetReplicaPort(const ReplicaPort &port, p4v1::Replica *replica) {
  switch (port.port_kind) {
    case p4v1::Replica::kEgressPort:
      replica->set_egress_port(static_cast<uint32_t>(port.port_id));
      RETURN_OK_STATUS();
    case p4v1::Replica::kPort:
      *replica->mutable_port() =
          common::pi_port_to_bytestring(port.port_id, port.num_bytes);
      RETURN_OK_STATUS();

    default:
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Unset `port_kind` in internal `ReplicaPort` representation");
  }
}

}  // namespace

/* static */ Status
PreMcMgr::make_new_group(const GroupEntry &group_entry, Group *group) {
  for (const auto &replica : group_entry.replicas()) {
    auto rid = static_cast<RId>(replica.instance());
    ReplicaPort eg_port;
    RETURN_IF_ERROR(GetReplicaPort(replica, &eg_port));
    auto &node = group->nodes[rid];
    auto p = node.eg_ports.insert(std::move(eg_port));
    if (!p.second) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Duplicate replica in multicast group");
    }
  }
  RETURN_OK_STATUS();
}

/* static */ void
PreMcMgr::read_group(
    GroupId group_id, const Group &group, GroupEntry *group_entry) {
  group_entry->set_multicast_group_id(group_id);
  // add all the replicas for the group: the order may defer from the order of
  // the replicas in the corresponding WriteRequest, but this is allowed by the
  // P4Runtime specification.
  for (const auto &p_node : group.nodes) {
    auto rid = static_cast<uint32_t>(p_node.first);
    for (auto port : p_node.second.eg_ports) {
      auto *replica = group_entry->add_replicas();
      SetReplicaPort(port, replica);
      replica->set_instance(rid);
    }
  }
}

namespace {

std::vector<pi_mc_port_t> GetPiEgressPorts(
    const std::set<ReplicaPort> &ports) {
  std::vector<pi_mc_port_t> result;
  result.reserve(ports.size());
  for (const auto &port : ports) result.push_back(port.port_id);
  return result;
}

}  // namespace


Status
PreMcMgr::create_and_attach_node(McSessionTemp *session,
                                 pi_mc_grp_handle_t group_h,
                                 RId rid,
                                 Node *node) {
  pi_status_t pi_status;
  std::vector<pi_mc_port_t> eg_ports_seq = GetPiEgressPorts(node->eg_ports);
  pi_status = pi_mc_node_create(
      session->get(), device_id, rid,
      eg_ports_seq.size(), eg_ports_seq.data(), &node->node_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when modifying multicast group in target");
  }
  session->cleanup_task_push(std::unique_ptr<NodeCleanupTask>(
      new NodeCleanupTask(this, node->node_h)));
  pi_status = pi_mc_grp_attach_node(
      session->get(), device_id, group_h, node->node_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when modifying multicast group in target");
  }
  session->cleanup_task_push(std::unique_ptr<NodeDetachCleanupTask>(
      new NodeDetachCleanupTask(this, group_h, node->node_h)));
  RETURN_OK_STATUS();
}

Status
PreMcMgr::modify_node(const McSessionTemp &session, const Node &node) {
  pi_status_t pi_status;
  std::vector<pi_mc_port_t> eg_ports_seq = GetPiEgressPorts(node.eg_ports);
  pi_status = pi_mc_node_modify(session.get(), device_id, node.node_h,
                                eg_ports_seq.size(), eg_ports_seq.data());
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when modifying multicast group in target");
  }
  RETURN_OK_STATUS();
}

Status
PreMcMgr::detach_and_delete_node(const McSessionTemp &session,
                                 pi_mc_grp_handle_t group_h,
                                 const Node &node) {
  pi_status_t pi_status;
  pi_status = pi_mc_grp_detach_node(
      session.get(), device_id, group_h, node.node_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when modifying multicast group in target");
  }
  pi_status = pi_mc_node_delete(session.get(), device_id, node.node_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when modifying multicast group in target");
  }
  RETURN_OK_STATUS();
}

namespace {

template <typename Fn, typename ...Args>
Status execute_operation(const Fn &fn, PreMcMgr *mgr, Args &&...args) {
  McSessionTemp session;
  auto status = (mgr->*fn)(&session, std::forward<Args>(args)...);
  auto cleanup_status = session.local_cleanup();
  return IS_OK(cleanup_status) ? status : cleanup_status;
}

}  // namespace

Status
PreMcMgr::group_create_(McSessionTemp *session,
                        GroupId group_id,
                        Group *group) {
  session->cleanup_scope_push();
  auto pi_status = pi_mc_grp_create(
      session->get(), device_id, group_id, &group->group_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(Code::UNKNOWN,
                        "Error when creating multicast group in target");
  }
  session->cleanup_task_push(std::unique_ptr<GroupCleanupTask>(
      new GroupCleanupTask(this, group->group_h)));
  for (auto &node_p : group->nodes) {
    RETURN_IF_ERROR(create_and_attach_node(
        session, group->group_h, node_p.first, &node_p.second));
  }
  session->cleanup_scope_pop();
  RETURN_OK_STATUS();
}

Status
PreMcMgr::group_create(const GroupEntry &group_entry, GroupOwner owner) {
  auto group_id = static_cast<GroupId>(group_entry.multicast_group_id());
  Lock lock(mutex);
  if (groups.find(group_id) != groups.end())
    RETURN_ERROR_STATUS(Code::ALREADY_EXISTS, "Multicast group already exists");

  Group group;
  group.owner = owner;
  RETURN_IF_ERROR(make_new_group(group_entry, &group));

  RETURN_IF_ERROR(execute_operation(
      &PreMcMgr::group_create_, this, group_id, &group));

  groups.emplace(group_id, std::move(group));
  RETURN_OK_STATUS();
}

Status
PreMcMgr::group_modify_(McSessionTemp *session,
                        GroupId group_id,
                        Group *old_group,
                        Group *new_group) {
  (void) group_id;
  session->cleanup_scope_push();
  for (auto &node_p : new_group->nodes) {
    auto rid = node_p.first;
    auto old_node_it = old_group->nodes.find(rid);
    if (old_node_it == old_group->nodes.end()) {
      RETURN_IF_ERROR(create_and_attach_node(
          session, new_group->group_h, node_p.first, &node_p.second));
    } else {
      node_p.second.node_h = old_node_it->second.node_h;
      if (node_p.second.eg_ports != old_node_it->second.eg_ports)
        RETURN_IF_ERROR(modify_node(*session, node_p.second));
      old_group->nodes.erase(old_node_it);
    }
  }
  // if a call to create_and_attach_node fails, we cleanup all the nodes we have
  // created
  session->cleanup_scope_pop();
  for (auto &node_p : old_group->nodes) {
    RETURN_IF_ERROR(detach_and_delete_node(
        *session, new_group->group_h, node_p.second));
  }
  RETURN_OK_STATUS();
}

Status
PreMcMgr::group_modify(const GroupEntry &group_entry) {
  auto group_id = static_cast<GroupId>(group_entry.multicast_group_id());
  Lock lock(mutex);
  auto group_it = groups.find(group_id);
  if (group_it == groups.end())
    RETURN_ERROR_STATUS(Code::NOT_FOUND, "Multicast group does not exist");
  auto &old_group = group_it->second;

  Group new_group;
  new_group.group_h = old_group.group_h;
  new_group.owner = old_group.owner;
  RETURN_IF_ERROR(make_new_group(group_entry, &new_group));

  // if one node fails to be created / attached, we cleanup all the created
  // nodes, and keep the old group definition
  // detach_and_delete_node is unlikely to fail so we don't accomodate for that
  // case for now
  RETURN_IF_ERROR(execute_operation(
      &PreMcMgr::group_modify_, this, group_id, &old_group, &new_group));

  group_it->second = std::move(new_group);
  RETURN_OK_STATUS();
}

Status
PreMcMgr::group_delete(const GroupEntry &group_entry) {
  auto group_id = static_cast<GroupId>(group_entry.multicast_group_id());
  Lock lock(mutex);
  auto group_it = groups.find(group_id);
  if (group_it == groups.end())
    RETURN_ERROR_STATUS(Code::NOT_FOUND, "Multicast group does not exist");
  auto& group = group_it->second;

  McSessionTemp session;

  for (auto& node_p : group.nodes) {
    RETURN_IF_ERROR(detach_and_delete_node(
        session, group.group_h, node_p.second));
  }

  auto pi_status = pi_mc_grp_delete(session.get(), device_id, group.group_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when deleting multicast group in target");
  }

  groups.erase(group_id);
  RETURN_OK_STATUS();
}

Status
PreMcMgr::group_read(const GroupEntry &group_entry,
                     p4v1::ReadResponse *response) const {
  auto group_id = static_cast<GroupId>(group_entry.multicast_group_id());

  auto add_group_to_response = [response](GroupId group_id,
                                          const Group &group) {
    auto *entry = response->add_entities()
      ->mutable_packet_replication_engine_entry()
      ->mutable_multicast_group_entry();
    read_group(group_id, group, entry);
  };

  Lock lock(mutex);
  if (group_id == 0) {  // wildcard read
    for (const auto &p_group : groups) {
      // Do not include groups created internally (for clone sessions).
      // If groups was a map (ordered), we could break and stop the iteration
      // here. However, given that we also do a lot of single-value lookups in
      // groups, it is not clear which data structure is better.
      if (p_group.first >= first_reserved_group_id()) continue;
      add_group_to_response(p_group.first, p_group.second);
    }
  } else {
    auto group_it = groups.find(group_id);
    if (group_it == groups.end())
      RETURN_ERROR_STATUS(Code::NOT_FOUND, "Multicast group does not exist");
    add_group_to_response(group_entry.multicast_group_id(), group_it->second);
  }

  RETURN_OK_STATUS();
}

Status
PreMcMgr::group_read_one(GroupId group_id, GroupEntry *group_entry) const {
  Lock lock(mutex);
  auto group_it = groups.find(group_id);
  if (group_it == groups.end())
    RETURN_ERROR_STATUS(Code::NOT_FOUND, "Multicast group does not exist");
  read_group(group_id, group_it->second, group_entry);
  RETURN_OK_STATUS();
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
