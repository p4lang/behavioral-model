// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/actions.h>
#include <bm/bm_sim/control_action.h>
#include <bm/bm_sim/packet.h>

#include <string>

namespace bm {

ControlAction::ControlAction(const std::string &name, p4object_id_t id)
    : ControlFlowNode(name, id) { }

ControlAction::ControlAction(const std::string &name, p4object_id_t id,
                             std::unique_ptr<SourceInfo> source_info)
    : ControlFlowNode(name, id, std::move(source_info)) { }

void
ControlAction::set_next_node(ControlFlowNode *next_node) {
  this->next_node = next_node;
}

void
ControlAction::set_action(ActionFn *action) {
  this->action = action;
}

const ControlFlowNode *
ControlAction::operator()(Packet *pkt) const {
  assert(action);
  ActionFnEntry action_entry(action);
  // TODO(unknown): log action call with source information, or ActionFnEntry
  // log is sufficient?
  action_entry(pkt);
  return next_node;
}

}  // namespace bm
