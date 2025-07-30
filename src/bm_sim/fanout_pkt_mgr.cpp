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

#include <bm/bm_sim/fanout_pkt_mgr.h>

namespace bm {

std::vector<Packet *>& FanoutPktMgr::get_fanout_pkts(std::thread::id thread_id) {
    BMLOG_DEBUG("Getting fanout packets for thread {}", thread_id);
    auto it = fanout_vec_map.find(thread_id);
    if (it == fanout_vec_map.end()) {
        BMLOG_ERROR("No fanout vector registered for thread {}", thread_id);
        throw std::runtime_error("Fanout vector not found for thread");
    }
    return it->second;
}
void FanoutPktMgr::process_fanout(const Packet &pkt, EntryVec &entries, const MatchTableIndirect *match_table, bool hit) {
    std::vector<bm::Packet *> replica_pkts;
    replica_pkts.reserve(entries.size());

    for(auto entry : entries) {
        // TODO(Hao): apply_action in match_tables has a full procedure,
        //   need to make sure that directly applying the func does not
        //   cause any issues
        //Things to consider:
        // 1. set the entry index
        // 2. set meters
        // 3. set counters
        // 4. incorporate with the debugger?
        Packet* rep_pkt = pkt.clone_with_phv_and_registers_ptr().release();
        // why egress is not copied directly?
        rep_pkt->set_egress_port(pkt.get_egress_port());

        entry->action_fn(rep_pkt);
        BMLOG_DEBUG_PKT(*rep_pkt, "Action {} applied to fanout packet",
                        *entry);
        
        auto act_id = entry->action_fn.get_action_id();
        const ControlFlowNode *next_node = hit ?
            match_table->get_next_node(act_id) :
            match_table->get_next_node_default(act_id);
        if (next_node == nullptr) {
            BMLOG_DEBUG_PKT(*rep_pkt, "No next node for action id {}", act_id);
        } else {
            BMLOG_DEBUG_PKT(*rep_pkt, "Next node for action id {}: {}", act_id, next_node->get_name());
        }
        rep_pkt->set_next_node(next_node);
        replica_pkts.push_back(rep_pkt);
    }

    // Hao: remove the lock if can make sure threads access exclusive vecs
    std::lock_guard<std::mutex> lock(fanout_pkt_mutex);
    BMLOG_DEBUG("Processing fanout for thread {}", std::this_thread::get_id());
    auto cur_vec_it = fanout_vec_map.find(std::this_thread::get_id());
    if (cur_vec_it == fanout_vec_map.end()) {
        BMLOG_ERROR("No fanout vector registered for thread {}", std::this_thread::get_id());
        return;
    }
    auto &fanout_pkts = cur_vec_it->second;
    for (auto rep_pkt : replica_pkts) {
        fanout_pkts.push_back(rep_pkt);
    }
}




}