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
#ifndef BM_BM_SIM_FANOUT_PKT_MGR_H_
#define BM_BM_SIM_FANOUT_PKT_MGR_H_

#include "logger.h"
#include "packet.h"
#include "match_tables.h"
#include "action_profile.h"
#include <vector>

namespace bm {
class MatchTableIndirect;
using bm::ActionProfile;
using EntryVec = const std::vector<const ActionEntry*>;
using SelectorIface = ActionProfile::GroupSelectionIface;

struct FanoutCtx {
  bool hit{false};
  std::vector<Packet *> fanout_pkts;
  const Packet * cur_pkt{nullptr};
  ActionProfile *action_profile{nullptr};
  MatchTableIndirect *cur_table{nullptr};
};

class FanoutPktSelection: public SelectorIface{
  public:
    using grp_hdl_t = ActionProfile::grp_hdl_t;
    using mbr_hdl_t = ActionProfile::mbr_hdl_t;
    using hash_t = ActionProfile::hash_t;
    using MatchErrorCode = bm::MatchErrorCode;

    FanoutPktSelection() = default;
  
    void add_member_to_group(grp_hdl_t grp, mbr_hdl_t mbr) override;
  
    void remove_member_from_group(grp_hdl_t grp, mbr_hdl_t mbr) override;
  
    mbr_hdl_t get_from_hash(grp_hdl_t grp, hash_t h) const override;
  
    void reset() override {}
  
  private:
    std::unordered_map<grp_hdl_t, std::vector<mbr_hdl_t>> groups;
};

class FanoutPktMgr {
public:
    FanoutPktMgr(const FanoutPktMgr&) = delete;
    FanoutPktMgr& operator=(const FanoutPktMgr&) = delete;
    static FanoutPktMgr& instance() {
      static FanoutPktMgr instance_;
      return instance_;
    }

    inline void register_thread(std::thread::id thread_id) {
      BMLOG_DEBUG("Registering thread {}", thread_id);
      fanout_ctx_map.emplace(thread_id, FanoutCtx());
    }
    inline SelectorIface* get_grp_selector() {
      return grp_selector;
    }



    std::vector<Packet *>& get_fanout_pkts();
    FanoutCtx& get_fanout_ctx();
    void set_ctx(MatchTableIndirect *table, const Packet &pkt, ActionProfile *action_profile, bool hit);
    void reset_ctx();
    void replicate_for_entries(const std::vector<const ActionEntry*> &entries);

    std::mutex fanout_pkt_mutex;
    // TODO(Hao): deduplicate packets fanout, optional


private:
    FanoutPktMgr() = default;
    std::unordered_map<std::thread::id, FanoutCtx> fanout_ctx_map; 
    FanoutPktSelection fanout_selection;
    SelectorIface* grp_selector{&fanout_selection};
};

} // namespace bm

#endif  // BM_BM_SIM_FANOUT_PKT_MGR_H_