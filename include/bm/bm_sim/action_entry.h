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

#ifndef BM_BM_SIM_ACTION_ENTRY_H_
#define BM_BM_SIM_ACTION_ENTRY_H_

#include <iosfwd>
#include <utility>

#include "actions.h"
#include "control_flow.h"

namespace bm {

struct ActionEntry {
  ActionEntry() { }

  ActionEntry(ActionFnEntry action_fn, const ControlFlowNode *next_node)
      : action_fn(std::move(action_fn)), next_node(next_node) { }

  void dump(std::ostream *stream) const {
    action_fn.dump(stream);
  }

  void serialize(std::ostream *out) const;
  void deserialize(std::istream *in, const P4Objects &objs);

  friend std::ostream& operator<<(std::ostream &out, const ActionEntry &e) {
    e.dump(&out);
    return out;
  }

  ActionEntry(const ActionEntry &other) = default;
  ActionEntry &operator=(const ActionEntry &other) = default;

  ActionEntry(ActionEntry &&other) /*noexcept*/ = default;
  ActionEntry &operator=(ActionEntry &&other) /*noexcept*/ = default;

  ActionFnEntry action_fn{};
  const ControlFlowNode *next_node{nullptr};
};

}  // namespace bm

#endif  // BM_BM_SIM_ACTION_ENTRY_H_
