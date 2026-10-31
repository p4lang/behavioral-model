// SPDX-FileCopyrightText: 2026 The P4 Language Consortium
//
// SPDX-License-Identifier: Apache-2.0

#include <bm/bm_sim/actions.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/phv.h>
#include <gtest/gtest.h>

#include "simple_switch.h"
#include "register_access.h"

extern int import_primitives(SimpleSwitch *simple_switch);

TEST(SimpleSwitch_HeaderUnion, RemoveInvalidMember) {
  import_primitives(nullptr);
  bm::HeaderType short_type("short_t", 0), long_type("long_t", 1);
  short_type.push_back_field("f", 8);
  long_type.push_back_field("f", 32);
  bm::PHVFactory factory;
  factory.push_back_header("short", 0, short_type);
  factory.push_back_header("long", 1, long_type);
  factory.push_back_header_union("u", 0, {0, 1});
  auto source = bm::PHVSourceIface::make_phv_source();
  source->set_phv_factory(0, &factory);
  auto packet = bm::Packet::make_new(source.get());
  auto *phv = packet.get_phv();
  auto &header_union = phv->get_header_union(0);
  auto primitive = bm::ActionOpcodesMap::get_instance()->get_primitive(
      "remove_header");
  ASSERT_NE(nullptr, primitive);

  for (size_t active = 0; active < 2; active++) {
    for (size_t removed = 0; removed < 2; removed++) {
      header_union.at(active).mark_valid();
      const auto removed_bytes = header_union.at(active).get_nbytes_packet();
      packet.set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, 64);
      bm::ActionFn action("remove", 0, 0);
      action.push_back_primitive(primitive.get());
      action.parameter_push_back_header(removed);
      bm::ActionFnEntry entry(&action);
      entry(&packet);
      EXPECT_FALSE(header_union.is_valid());
      EXPECT_FALSE(header_union.at(0).is_valid());
      EXPECT_FALSE(header_union.at(1).is_valid());
      EXPECT_EQ(64u - removed_bytes,
                packet.get_register(RegisterAccess::PACKET_LENGTH_REG_IDX));
      // Removing an already-invalid union must not subtract its length again.
      entry(&packet);
      EXPECT_EQ(64u - removed_bytes,
                packet.get_register(RegisterAccess::PACKET_LENGTH_REG_IDX));
    }
  }
}
