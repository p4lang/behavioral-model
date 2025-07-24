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
#ifndef BM_BM_SIM_FANOUT_PKT_VEC_H_
#define BM_BM_SIM_FANOUT_PKT_VEC_H_

#include "logger.h"
#include "packet.h"
#include "match_tables.h"
#include <vector>

namespace bm {
class MatchTableAbstract;
// TODO(Hao): should this be per ingress thread or just global?
class FanoutPktVec {
public:
    FanoutPktVec(const FanoutPktVec&) = delete;
    FanoutPktVec& operator=(const FanoutPktVec&) = delete;

    static FanoutPktVec& instance() {
        static FanoutPktVec instance_;
        return instance_;
    }

    void set_next_nodes(const MatchTableAbstract *match_table, bool hit);
    inline void add_fanout_pkts_w_act_id(Packet *pkt, p4object_id_t act_id) {
        fanout_pkts_w_act_id.emplace_back(pkt, act_id);
    }

    std::mutex fanout_pkt_vec_mutex;
    // Fanout pkts will first be added to fanout_pkts
    // in order to get the corresponding next table node.
    // After the next_node is set, the pkt will be added to fanout_pkts
    std::vector<Packet *> fanout_pkts;
    // TODO(Hao): deduplicate packets fanout, optional


private:
    FanoutPktVec() = default;

    std::vector<std::pair<Packet *, p4object_id_t>> fanout_pkts_w_act_id;

};

} // namespace bm

#endif  // BM_BM_SIM_FANOUT_PKT_VEC_H_