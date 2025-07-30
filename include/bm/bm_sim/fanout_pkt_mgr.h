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
#include <vector>

namespace bm {
class MatchTableIndirect;

// TODO(Hao): should this be per ingress thread or just global?
class FanoutPktMgr {
public:
    using EntryVec = const std::vector<const ActionEntry*>;


    FanoutPktMgr(const FanoutPktMgr&) = delete;
    FanoutPktMgr& operator=(const FanoutPktMgr&) = delete;
    static FanoutPktMgr& instance() {
        static FanoutPktMgr instance_;
        return instance_;
    }

    inline void register_thread(std::thread::id thread_id) {
        BMLOG_DEBUG("Registering thread {}", thread_id);
        fanout_vec_map.emplace(thread_id, std::vector<Packet *>());
    }

    std::vector<Packet *>& get_fanout_pkts(std::thread::id thread_id);
    void process_fanout(const Packet &pkt, EntryVec &entries, const MatchTableIndirect *match_table, bool hit);

    std::mutex fanout_pkt_mutex;
    std::unordered_map<std::thread::id, std::vector<Packet *>> fanout_vec_map; 
    // TODO(Hao): deduplicate packets fanout, optional


private:
    FanoutPktMgr() = default;

};

} // namespace bm

#endif  // BM_BM_SIM_FANOUT_PKT_MGR_H_