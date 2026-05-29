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

#ifndef BM_BM_SIM_CONDITIONALS_H_
#define BM_BM_SIM_CONDITIONALS_H_

#include <memory>
#include <string>
#include <utility>

#include "phv.h"
#include "control_flow.h"
#include "expressions.h"

namespace bm {

class Conditional
  : public ControlFlowNode, public Expression {
 public:
  Conditional(const std::string &name, p4object_id_t id)
    : ControlFlowNode(name, id) {}
  Conditional(const std::string &name, p4object_id_t id,
              std::unique_ptr<SourceInfo> source_info)
    : ControlFlowNode(name, id, std::move(source_info)) {}

  bool eval(const PHV &phv) const {
    return eval_bool(phv);
  }

  void set_next_node_if_true(ControlFlowNode *next_node) {
    true_next = next_node;
  }

  void set_next_node_if_false(ControlFlowNode *next_node) {
    false_next = next_node;
  }

  // return pointer to next control flow node
  const ControlFlowNode *operator()(Packet *pkt) const override;

  Conditional(const Conditional &other) = delete;
  Conditional &operator=(const Conditional &other) = delete;

  Conditional(Conditional &&other) /*noexcept*/ = default;
  Conditional &operator=(Conditional &&other) /*noexcept*/ = default;

 private:
  ControlFlowNode *true_next{nullptr};
  ControlFlowNode *false_next{nullptr};
};

}  // namespace bm

#endif  // BM_BM_SIM_CONDITIONALS_H_
