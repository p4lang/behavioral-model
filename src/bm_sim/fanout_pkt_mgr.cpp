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
#include <bm/bm_sim/event_logger.h>

namespace bm {


void FanoutPktSelection::add_member_to_group(grp_hdl_t grp, mbr_hdl_t mbr) {
  (void) grp;
  (void) mbr;
}

void FanoutPktSelection::remove_member_from_group(grp_hdl_t grp, mbr_hdl_t mbr) {
  (void) grp;
  (void) mbr;
}

FanoutPktSelection::mbr_hdl_t FanoutPktSelection::get_from_hash(grp_hdl_t grp, hash_t h) const {
  (void)h;
  auto &ctx = FanoutPktMgr::instance().get_fanout_ctx();
  auto *action_profile = ctx.action_profile;
  if (!action_profile) {
    BMLOG_ERROR("No action profile set for fanout packet selection");
    throw std::runtime_error("No action profile set for fanout packet selection");
  }

  std::vector<mbr_hdl_t> mbrs = action_profile->get_all_mbrs_from_grp(grp);
  mbr_hdl_t selected_mbr = mbrs.back();
  mbrs.pop_back();
  
  auto entries = action_profile->get_entries_with_mbrs(mbrs);
  BMLOG_DEBUG("Fanout Selected member {} from group {} with hash {} with number of entries {}", selected_mbr, grp, h, entries.size());
  FanoutPktMgr::instance().replicate_for_entries(entries);
  return selected_mbr;
}


std::vector<Packet *>& FanoutPktMgr::get_fanout_pkts() {
    std::thread::id thread_id = std::this_thread::get_id();
    BMLOG_DEBUG("Getting fanout packets for thread {}", thread_id);

    std::lock_guard<std::mutex> lock(fanout_pkt_mutex);
    auto it = fanout_ctx_map.find(thread_id);
    if (it == fanout_ctx_map.end()) {
        BMLOG_ERROR("No fanout vector registered for thread {}", thread_id);
        throw std::runtime_error("Fanout vector not found for thread");
    }
    return it->second.fanout_pkts;
}

FanoutCtx& FanoutPktMgr::get_fanout_ctx() {
    std::thread::id thread_id = std::this_thread::get_id();
    auto it = fanout_ctx_map.find(thread_id);

    std::lock_guard<std::mutex> lock(fanout_pkt_mutex);
    if (it == fanout_ctx_map.end()) {
        BMLOG_ERROR("No fanout context registered for thread {}", thread_id);
        throw std::runtime_error("Fanout context not found for thread");
    }
    return it->second;
}
void FanoutPktMgr::set_ctx(MatchTableIndirect *table, const Packet &pkt, ActionProfile *action_profile, bool hit) {
    auto &ctx = get_fanout_ctx();
    ctx.cur_table = table;
    ctx.cur_pkt = &pkt;
    ctx.action_profile = action_profile;
    ctx.hit = hit;
}

void FanoutPktMgr::reset_ctx() {
    auto &ctx = get_fanout_ctx();
    ctx.cur_table = nullptr;
    ctx.cur_pkt = nullptr;
    ctx.action_profile = nullptr;
}

void FanoutPktMgr::replicate_for_entries(const std::vector<const ActionEntry*> &entries) {
    auto &fanout_pkts = get_fanout_pkts();
    auto &ctx = get_fanout_ctx();
    auto *match_table = ctx.cur_table;
    const Packet &pkt = *ctx.cur_pkt;
    bool hit = ctx.hit;

    // for event logger
    uint64_t parent_pkt_copy_id = pkt.get_copy_id();
    uint64_t table_id = match_table->get_id();
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
        // why egress is not copied directly? i have to set it here
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
        fanout_pkts.push_back(rep_pkt);

        BMELOG(fanout_gen, *rep_pkt, table_id, parent_pkt_copy_id);
    }

    reset_ctx();
}




}