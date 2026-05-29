// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <gtest/gtest.h>

#include <bm/bm_sim/stateful.h>

using bm::RegisterArray;

// Google Test fixture for Stateful tests
class StatefulTest : public ::testing::Test {
 protected:
  static constexpr size_t size = 128;
  static constexpr int bitwidth = 32;
  RegisterArray reg_array;

  StatefulTest()
      : reg_array("test", 0, size, bitwidth) { }
};

constexpr size_t StatefulTest::size;
constexpr int StatefulTest::bitwidth;

TEST_F(StatefulTest, Simple) {
  int test_v(99);
  auto lock = reg_array.unique_lock();
  for (auto &r : reg_array)
    r.set(test_v);
  for (const auto &r : reg_array)
    ASSERT_EQ(test_v, r.get<decltype(test_v)>());
  ASSERT_EQ(test_v, reg_array.at(0).get<decltype(test_v)>());
  ASSERT_EQ(test_v, reg_array[0].get<decltype(test_v)>());
}

TEST_F(StatefulTest, OutOfRange) {
  auto lock = reg_array.unique_lock();
  ASSERT_THROW(reg_array.at(size), std::out_of_range);
}

TEST_F(StatefulTest, Notifier) {
  size_t index(0);
  {
    auto lock = reg_array.unique_lock();
    reg_array.register_notifier([&index](size_t idx) { index = idx; });
  }
  {
    size_t index_test_v(54);
    int test_v(99);
    auto lock = reg_array.unique_lock();
    const auto &r = reg_array.at(index_test_v);
    reg_array.at(index_test_v).set(test_v);
    ASSERT_EQ(test_v, r.get<decltype(test_v)>());
    ASSERT_EQ(index_test_v, index);
  }
}
