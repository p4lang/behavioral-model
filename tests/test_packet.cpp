/* Copyright 2013-present Barefoot Networks, Inc.
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

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <gtest/gtest.h>

#include <vector>

#include "bm_sim/packet.h"

TEST(CopyIdGenerator, Test) {
  CopyIdGenerator gen;
  packet_id_t packet_id = 0;
  ASSERT_EQ(0u, gen.get(packet_id));
  ASSERT_EQ(1u, gen.add_one(packet_id));
  ASSERT_EQ(1u, gen.get(packet_id));
  ASSERT_EQ(2u, gen.add_one(packet_id));
  gen.remove_one(packet_id);
  ASSERT_EQ(1u, gen.get(packet_id));
  gen.reset(packet_id);
  ASSERT_EQ(0u, gen.get(packet_id));
}

class PHVSourceTest : public PHVSourceIface {
 public:
  explicit PHVSourceTest(size_t size)
      : phv_factories(size, nullptr), created(size, 0u), destroyed(size, 0u) { }

  size_t get_created(size_t cxt) {
    return created.at(cxt);
  }

  size_t get_destroyed(size_t cxt) {
    return destroyed.at(cxt);
  }

 private:
  std::unique_ptr<PHV> get_(size_t cxt) override {
    assert(phv_factories[cxt]);
    ++created.at(cxt);
    return phv_factories[cxt]->create();
  }

  void release_(size_t cxt, std::unique_ptr<PHV> phv) override {
    // let the PHV be destroyed
    (void) cxt; (void) phv;
    ++destroyed.at(cxt);
  }

  void set_phv_factory_(size_t cxt, const PHVFactory *factory) override {
    phv_factories.at(cxt) = factory;
  }

  std::vector<const PHVFactory *> phv_factories;
  std::vector<size_t> created;
  std::vector<size_t> destroyed;
};

// Google Test fixture for Packet tests
class PacketTest : public ::testing::Test {
 protected:
  PHVFactory phv_factory;

  std::unique_ptr<PHVSourceTest> phv_source{nullptr};

  PacketTest()
      : phv_source(new PHVSourceTest(2)) { }

  virtual void SetUp() {
    phv_source->set_phv_factory(0, &phv_factory);
    phv_source->set_phv_factory(1, &phv_factory);
  }

  // virtual void TearDown() { }

  Packet get_packet(size_t cxt, packet_id_t id = 0) {
    // dummy packet, never parsed
    return Packet::make_new(cxt, 0, id, 0, 0, PacketBuffer(), phv_source.get());
  }
};

TEST_F(PacketTest, Packet) {
  const size_t first_cxt = 0;
  const size_t other_cxt = 1;
  ASSERT_EQ(0u, phv_source->get_created(first_cxt));
  ASSERT_EQ(0u, phv_source->get_created(other_cxt));
  auto packet = get_packet(first_cxt);
  ASSERT_EQ(1u, phv_source->get_created(first_cxt));
  ASSERT_EQ(0u, phv_source->get_created(other_cxt));
}

TEST_F(PacketTest, ChangeContext) {
  const size_t first_cxt = 0;
  const size_t other_cxt = 1;
  auto packet = get_packet(first_cxt);
  ASSERT_EQ(1u, phv_source->get_created(first_cxt));
  ASSERT_EQ(0u, phv_source->get_created(other_cxt));
  packet.change_context(other_cxt);
  ASSERT_EQ(1u, phv_source->get_created(first_cxt));
  ASSERT_EQ(1u, phv_source->get_destroyed(first_cxt));
  ASSERT_EQ(1u, phv_source->get_created(other_cxt));
  ASSERT_EQ(0u, phv_source->get_destroyed(other_cxt));
}
