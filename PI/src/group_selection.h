/*
 * SPDX-FileCopyrightText: 2019 Barefoot Networks, Inc.
 * Copyright 2019-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef SRC_GROUP_SELECTION_H_
#define SRC_GROUP_SELECTION_H_

#include <bm/bm_sim/action_profile.h>
#include <bm/bm_sim/match_error_codes.h>
#include <bm/bm_sim/ras.h>

#include <unordered_map>
#include <unordered_set>

namespace pibmv2 {

class GroupSelection : public bm::ActionProfile::GroupSelectionIface {
 public:
  using mbr_hdl_t = bm::ActionProfile::mbr_hdl_t;
  using grp_hdl_t = bm::ActionProfile::grp_hdl_t;
  using MatchErrorCode = bm::MatchErrorCode;

  MatchErrorCode activate_member(grp_hdl_t grp, mbr_hdl_t mbr);
  MatchErrorCode deactivate_member(grp_hdl_t grp, mbr_hdl_t mbr);

 private:
  using hash_t = bm::ActionProfile::hash_t;

  void add_member_to_group(grp_hdl_t grp, mbr_hdl_t mbr) override;
  void remove_member_from_group(grp_hdl_t grp, mbr_hdl_t mbr) override;

  mbr_hdl_t get_from_hash(grp_hdl_t grp, hash_t h) const override;

  void reset() override;

  class GroupInfo {
   public:
    MatchErrorCode activate_member(mbr_hdl_t mbr);
    MatchErrorCode deactivate_member(mbr_hdl_t mbr);
    void add_member(mbr_hdl_t mbr);
    void remove_member(mbr_hdl_t mbr);
    mbr_hdl_t get_from_hash(hash_t h) const;
    size_t size() const;

   private:
    bm::RandAccessUIntSet activated_members{};
    std::unordered_set<mbr_hdl_t> members;
  };

  mutable std::mutex mutex{};
  std::unordered_map<grp_hdl_t, GroupInfo> groups{};
};

}  // namespace pibmv2

#endif  // SRC_GROUP_SELECTION_H_
