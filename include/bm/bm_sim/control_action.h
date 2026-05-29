/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef BM_BM_SIM_CONTROL_ACTION_H_
#define BM_BM_SIM_CONTROL_ACTION_H_

#include <memory>
#include <string>

#include "control_flow.h"

namespace bm {

class Packet;
class ActionFn;

class ControlAction : public ControlFlowNode {
 public:
  ControlAction(const std::string &name, p4object_id_t id);

  ControlAction(const std::string &name, p4object_id_t id,
                std::unique_ptr<SourceInfo> source_info);

  void set_next_node(ControlFlowNode *next_node);

  void set_action(ActionFn *action);

  const ControlFlowNode *operator()(Packet *pkt) const override;

 private:
  ControlFlowNode *next_node{nullptr};
  ActionFn *action;
};

}  // namespace bm

#endif  // BM_BM_SIM_CONTROL_ACTION_H_
