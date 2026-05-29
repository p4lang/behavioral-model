/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Srikrishna Gopu (krishna@barefootnetworks.com)
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

//! @file simple_pre_lag.h

#ifndef BM_BM_SIM_SIMPLE_PRE_LAG_H_
#define BM_BM_SIM_SIMPLE_PRE_LAG_H_

#include <string>
#include <unordered_map>
#include <vector>

#include "pre.h"
#include "simple_pre.h"

namespace bm {

//! Enhances McSimplePre with LAG (link aggregation) support.
class McSimplePreLAG : public McSimplePre {
 public:
  static constexpr int LAG_MAX_ENTRIES = 256;
  using lag_id_t = uint16_t;

  explicit McSimplePreLAG(
      int mgid_table_size = McSimplePre::DEFAULT_MGID_TABLE_SIZE,
      int l1_max_entries = McSimplePre::DEFAULT_L1_MAX_ENTRIES,
      int l2_max_entries = McSimplePre::DEFAULT_L2_MAX_ENTRIES)
      : McSimplePre(mgid_table_size, l1_max_entries, l2_max_entries) {}

  McReturnCode mc_node_create(const rid_t rid,
                              const PortMap &port_map,
                              const LagMap &lag_map,
                              l1_hdl_t *l1_hdl);
  McReturnCode mc_node_update(const l1_hdl_t l1_hdl,
                              const PortMap &port_map,
                              const LagMap &lag_map);

  McReturnCode mc_set_lag_membership(const lag_id_t lag_index,
                                     const PortMap &port_map);

  std::string mc_get_entries() const;

  void reset_state();

  std::vector<McOut> replicate(const McIn) const;

 private:
  struct LagEntry {
    uint16_t member_count;
    PortMap port_map{};

    LagEntry() {}
    LagEntry(uint16_t member_count, const PortMap &port_map)
        : member_count(member_count), port_map(port_map) {}
  };

  std::unordered_map<lag_id_t, LagEntry> lag_entries{};
};

}  // namespace bm

#endif  // BM_BM_SIM_SIMPLE_PRE_LAG_H_
