// SPDX-FileCopyrightText: 2026 The P4 Language Consortium
//
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>

#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/phv.h>
#include <bm/bm_sim/phv_source.h>

#include <memory>
#include <string>
#include <vector>

#include "externs/pna_hash.h"

using namespace bm;

namespace {

class PNA_HashTest : public ::testing::Test {
 protected:
  HeaderType header_type{"test_t", 0};
  header_id_t header_id{0};
  PHVFactory phv_factory;
  std::unique_ptr<PHVSourceIface> phv_source{PHVSourceIface::make_phv_source()};
  std::unique_ptr<Packet> packet{nullptr};
  pna::PNA_Hash hash;

  virtual void SetUp() {
    header_type.push_back_field("data", 32);
    header_type.push_back_field("dst", 16);
    phv_factory.push_back_header("test", header_id, header_type);
    phv_source->set_phv_factory(0, &phv_factory);
    packet = std::unique_ptr<Packet>(new Packet(Packet::make_new(
        64, PacketBuffer(128), phv_source.get())));

    hash._register_attributes();
    hash._set_attribute<std::string>("algo", "crc16");
    hash.init();

    // crc16 of these four bytes is 0x5d8a, see HashTest.Crc16.
    packet->get_phv()->get_field("test.data").set(0x0bb81f90);
  }
};

}  // namespace

TEST_F(PNA_HashTest, GetHashMod) {
  auto phv = packet->get_phv();
  auto &dst = phv->get_field("test.dst");
  std::vector<Field> fields{phv->get_field("test.data")};

  // 0x5d8a % 10 is 6, plus a base of 6.
  hash.get_hash_mod(dst, Data(6), fields, Data(10));
  EXPECT_EQ(12u, dst.get<uint16_t>());
}

TEST_F(PNA_HashTest, GetHashModZeroMax) {
  auto phv = packet->get_phv();
  auto &dst = phv->get_field("test.dst");
  std::vector<Field> fields{phv->get_field("test.data")};

  // A max of 0 is treated as 1, so the result is always base.
  hash.get_hash_mod(dst, Data(6), fields, Data(0));
  EXPECT_EQ(6u, dst.get<uint16_t>());
}
