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

#ifndef BM_BM_SIM_TABLE_APPLY_H_
#define BM_BM_SIM_TABLE_APPLY_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include "control_flow.h"
#include "tables.h"

namespace bm {

// TableApply represents a specific application of a table in the control flow
// This allows the same table to be applied multiple times with different
// next nodes for each application
class TableApply : public ControlFlowNode {
 public:
  TableApply(const std::string &name, p4object_id_t id,
             MatchActionTable *table);

  const ControlFlowNode *operator()(Packet *pkt) const override;

  void set_next_node(p4object_id_t action_id, const ControlFlowNode *next_node);
  void set_next_node_hit(const ControlFlowNode *next_node);
  void set_next_node_miss(const ControlFlowNode *next_node);

  MatchActionTable *get_table() const { return table; }

 private:
  MatchActionTable *table;
  std::unordered_map<p4object_id_t, const ControlFlowNode *> next_nodes{};
  const ControlFlowNode *next_node_hit{nullptr};
  const ControlFlowNode *next_node_miss{nullptr};
  bool has_next_node_hit{false};
  bool has_next_node_miss{false};
};

}  // namespace bm

#endif  // BM_BM_SIM_TABLE_APPLY_H_
