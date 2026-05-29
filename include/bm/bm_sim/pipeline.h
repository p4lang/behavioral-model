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

//! @file pipeline.h

#ifndef BM_BM_SIM_PIPELINE_H_
#define BM_BM_SIM_PIPELINE_H_

#include <string>

#include "control_flow.h"
#include "named_p4object.h"

namespace bm {

//! Implements a P4 control flow. It essentially consists of a apply() method
//! which is in charge of sending the Packet through the correct match-action
//! tables and conditions.
class Pipeline : public NamedP4Object {
 public:
  Pipeline(const std::string &name, p4object_id_t id,
           ControlFlowNode *first_node)
    : NamedP4Object(name, id), first_node(first_node) {}

  //! Sends the \p pkt through the correct match-action tables and
  //! condiitons. Each step is determined based on the result of the previous
  //! step (table lookup or condition evaluation), according to the P4 control
  //! flow graph.
  void apply(Packet *pkt);

  //! Deleted copy constructor
  Pipeline(const Pipeline &other) = delete;
  //! Deleted copy assignment operator
  Pipeline &operator=(const Pipeline &other) = delete;

  //! Default move constructor
  Pipeline(Pipeline &&other) /*noexcept*/ = default;
  //! Default move assignment operator
  Pipeline &operator=(Pipeline &&other) /*noexcept*/ = default;

 private:
  ControlFlowNode *first_node;
};

}  // namespace bm

#endif  // BM_BM_SIM_PIPELINE_H_
