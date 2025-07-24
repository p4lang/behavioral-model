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

    void process_fanout(const Packet &pkt, EntryVec &entries, const MatchTableIndirect *match_table, bool hit);

    std::mutex fanout_pkt_mutex;
    // Fanout pkts will first be added to fanout_pkts
    // in order to get the corresponding next table node.
    // After the next_node is set, the pkt will be added to fanout_pkts
    std::vector<Packet *> fanout_pkts;
    // TODO(Hao): deduplicate packets fanout, optional


private:
    FanoutPktMgr() = default;

};

} // namespace bm

#endif  // BM_BM_SIM_FANOUT_PKT_MGR_H_