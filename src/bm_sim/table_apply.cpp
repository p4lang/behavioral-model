/* Copyright 2013-present Barefoot Networks, Inc.
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

#include <bm/bm_sim/table_apply.h>
#include <bm/bm_sim/action_entry.h>
#include <bm/bm_sim/debugger.h>
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/packet.h>

#include <string>

namespace bm {

TableApply::TableApply(const std::string &name, p4object_id_t id,
                       MatchActionTable *table)
    : ControlFlowNode(name, id), table(table) { }

const ControlFlowNode *
TableApply::operator()(Packet *pkt) const {
  // TODO(antonin) this is temporary while we experiment with the debugger
  DEBUGGER_NOTIFY_CTR(
      Debugger::PacketId::make(pkt->get_packet_id(), pkt->get_copy_id()),
      DBG_CTR_TABLE_APPLY | get_id());
  BMLOG_TRACE_PKT(*pkt, "Applying table application '{}'", get_name());

  // Apply the table and get the next node
  entry_handle_t handle;
  bool hit;
  const ControlFlowNode *next_node;

  // Lookup the table directly to get hit/miss information and action
  const ActionEntry &action_entry = table->get_match_table()->lookup(*pkt, &hit, &handle, &next_node);

  // Determine the next node based on the result
  const ControlFlowNode *next = nullptr;

  if (has_next_node_hit && has_next_node_miss) {
    // If we have hit/miss nodes defined, use those
    next = hit ? next_node_hit : next_node_miss;
  } else if (hit && !next_nodes.empty()) {
    // If we have action-specific next nodes, use those
    auto action_id = action_entry.action_fn.get_action_id();
    auto it = next_nodes.find(action_id);
    if (it != next_nodes.end()) {
      next = it->second;
    } else {
      // Fall back to the next_node from the lookup
      next = next_node;
    }
  } else {
    // Use the next_node from the lookup
    next = next_node;
  }

  DEBUGGER_NOTIFY_CTR(
      Debugger::PacketId::make(pkt->get_packet_id(), pkt->get_copy_id()),
      DBG_CTR_EXIT(DBG_CTR_TABLE_APPLY) | get_id());

  return next;
}

void
TableApply::set_next_node(p4object_id_t action_id, const ControlFlowNode *next_node) {
  next_nodes[action_id] = next_node;
}

void
TableApply::set_next_node_hit(const ControlFlowNode *next_node) {
  next_node_hit = next_node;
  has_next_node_hit = true;
}

void
TableApply::set_next_node_miss(const ControlFlowNode *next_node) {
  next_node_miss = next_node;
  has_next_node_miss = true;
}

}  // namespace bm
