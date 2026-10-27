// SPDX-FileCopyrightText: 2026 The P4 Language Consortium & Devansh Singh
//
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>

#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/phv.h>
#include <bm/bm_sim/phv_source.h>

#include "externs/psa_counter.h"
#include "externs/psa_meter.h"

using namespace bm;

namespace {

// Minimal packet fixture for testing extern execution without header parsing.
class PSA_MeterCounterBoundsTest : public ::testing::Test {
 protected:
  PHVFactory phv_factory;
  std::unique_ptr<PHVSourceIface> phv_source{PHVSourceIface::make_phv_source()};
  std::unique_ptr<Packet> packet{nullptr};

  virtual void SetUp() {
    phv_source->set_phv_factory(0, &phv_factory);
    packet = std::unique_ptr<Packet>(new Packet(Packet::make_new(
        64, PacketBuffer(128), phv_source.get())));
  }
};

}  // namespace

TEST_F(PSA_MeterCounterBoundsTest, MeterOutOfBoundsIndex) {
  psa::PSA_Meter meter;
  meter._register_attributes();
  meter._set_attribute<Data>("n_meters", Data(4));
  meter._set_attribute<std::string>("type", "packets");
  meter._set_attribute<Data>("rate_count", Data(1));
  meter._set_name_and_id("test_meter", 0);
  meter.init();
  meter._set_packet_ptr(packet.get());

  ASSERT_EQ(4u, meter.size());

  Data index(10);  // Out-of-bounds index (valid: 0..3)
  Data value(0xff);
  EXPECT_NO_THROW(meter.execute(index, value));
  // Verify output value remains unmodified
  EXPECT_EQ(Data(0xff), value);
}

TEST_F(PSA_MeterCounterBoundsTest, CounterOutOfBoundsIndex) {
  psa::PSA_Counter counter;
  counter._register_attributes();
  counter._set_attribute<Data>("n_counters", Data(4));
  counter._set_name_and_id("test_counter", 0);
  counter.init();
  counter._set_packet_ptr(packet.get());

  ASSERT_EQ(4u, counter.size());

  Data index(10);  // Out-of-bounds index (valid: 0..3)
  EXPECT_NO_THROW(counter.count(index));
  // Verify counter state remains unmutated
  Counter::counter_value_t bytes = 0, packets = 0;
  counter.get_counter(0).query_counter(&bytes, &packets);
  EXPECT_EQ(0u, bytes);
  EXPECT_EQ(0u, packets);
}
