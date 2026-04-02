/* Copyright 2025-present Contributors to the P4 Project
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

#include <memory>
#include <unordered_map>
#include <vector>
#include "logger.h"
#include "packet.h"
#include "match_tables.h"
#include "action_profile.h"

namespace bm {
class MatchTableIndirect;
using bm::ActionProfile;
using EntryVec = const std::vector<const ActionEntry*>;
using SelectorIface = ActionProfile::GroupSelectionIface;

struct FanoutCtx {
  bool hit{false};
  const Packet * cur_pkt{nullptr};
  ActionProfile *action_profile{nullptr};
  MatchTableIndirect *cur_table{nullptr};
  std::function<void(const bm::Packet *)> buffer_push_fn;

  explicit FanoutCtx(
    const std::function<void(const bm::Packet *)> &buffer_push_fn)
      : buffer_push_fn(buffer_push_fn) { }
};

class FanoutPktSelection: public SelectorIface{
 public:
    using grp_hdl_t = ActionProfile::grp_hdl_t;
    using mbr_hdl_t = ActionProfile::mbr_hdl_t;
    using hash_t = ActionProfile::hash_t;
    using MatchErrorCode = bm::MatchErrorCode;

    FanoutPktSelection() = default;

    // callbacks after member op, not actual member/group ops
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

    FanoutCtx& get_fanout_ctx();
    void set_ctx(MatchTableIndirect *table, const Packet &pkt,
                 ActionProfile *action_profile, bool hit);
    void reset_ctx();
    void replicate_for_entries(const std::vector<const ActionEntry*> &entries);

    // PI overwrite selector specified during P4Object init,
    // so we need to set the selector in switch start_and_return_
    void set_grp_selector() {
      for (const auto &ap : act_profs) {
        ap->set_group_selector(grp_selector);
      }
    }
    inline void register_thread(std::thread::id thread_id,
      const std::function<void(const bm::Packet *)> &buffer_push_fn) {
      BMLOG_DEBUG("Registering thread {}", thread_id);
      fanout_ctx_map.emplace(thread_id, FanoutCtx(buffer_push_fn));
    }

    // TODO(Hao): deduplicate packets fanout, optional
#ifdef BM_PKT_FANOUT_ON
    static constexpr bool pkt_fanout_on = true;
#else
    static constexpr bool pkt_fanout_on = false;
#endif
    std::mutex fanout_pkt_mutex;
    std::vector<ActionProfile*> act_profs;

 private:
    FanoutPktMgr() = default;
    std::unordered_map<std::thread::id, FanoutCtx> fanout_ctx_map;
    std::shared_ptr<SelectorIface>
      grp_selector{std::make_shared<FanoutPktSelection>()};
};

}  // namespace bm

#endif  // BM_BM_SIM_FANOUT_PKT_MGR_H_
