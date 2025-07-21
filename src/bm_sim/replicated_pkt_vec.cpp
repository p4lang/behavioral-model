/* Copyright 2013-present Contributors to the P4 Project
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

#include <bm/bm_sim/replicated_pkt_vec.h>

namespace bm {

void 
ReplicatedPktVec::set_next_nodes(const MatchTableAbstract *match_table, bool hit) {
    for (auto &pkt_act_id : replicated_pkts_w_act_id) {
        auto pkt = pkt_act_id.first;
        auto act_id = pkt_act_id.second;
        const ControlFlowNode *next_node = hit ?
            match_table->get_next_node(act_id) :
            match_table->get_next_node_default(act_id);
        if (next_node == nullptr) {
            BMLOG_DEBUG_PKT(*pkt, "No next node for action id {}", act_id);
        }else{
            BMLOG_DEBUG_PKT(*pkt, "Next node for action id {}: {}", act_id, next_node->get_name());
        }
        pkt->set_continue_node(next_node);
        replicated_pkts.push_back(pkt);
    }
    replicated_pkts_w_act_id.clear();
}
}