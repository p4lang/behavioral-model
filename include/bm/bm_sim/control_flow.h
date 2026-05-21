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

#ifndef BM_BM_SIM_CONTROL_FLOW_H_
#define BM_BM_SIM_CONTROL_FLOW_H_

#include <memory>
#include <string>
#include <utility>

#include "named_p4object.h"

namespace bm {

class Packet;

class ControlFlowNode : public NamedP4Object {
 public:
  ControlFlowNode(const std::string &name, p4object_id_t id)
      : NamedP4Object(name, id) { }
  ControlFlowNode(const std::string &name, p4object_id_t id,
                  std::unique_ptr<SourceInfo> source_info)
      : NamedP4Object(name, id, std::move(source_info)) {}

  virtual ~ControlFlowNode() = default;

  virtual const ControlFlowNode *operator()(Packet *pkt) const = 0;

  //! Deleted copy constructor
  ControlFlowNode(const ControlFlowNode &other) = delete;
  //! Deleted copy assignment operator
  ControlFlowNode &operator=(const ControlFlowNode &other) = delete;

  // The following are implictly deleted otherwise because of the user-defined
  // virtual destructor.

  //! Default move constructor
  ControlFlowNode(ControlFlowNode &&other) = default;
  //! Default assignment operator
  ControlFlowNode &operator=(ControlFlowNode &&other) = default;
};

}  // namespace bm

#endif  // BM_BM_SIM_CONTROL_FLOW_H_
