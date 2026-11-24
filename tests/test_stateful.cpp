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

#include <chrono>
#include <future>
#include <thread>

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

// A packet action owns this same lock for its entire register access.
TEST_F(StatefulTest, ResetWaitsForRegisterAccess) {
  auto lock = reg_array.unique_lock();
  reg_array[0].set(99);
  std::promise<void> started;
  std::promise<void> finished;
  auto completion = finished.get_future();
  std::thread resetter([&] {
    started.set_value();
    reg_array.reset_state();
    finished.set_value();
  });
  started.get_future().wait();
  const auto status = completion.wait_for(std::chrono::milliseconds(100));
  // Always release and join before assertions, including on failure.
  lock.unlock();
  resetter.join();
  EXPECT_EQ(std::future_status::timeout, status)
      << "reset_state completed while another thread owned the register lock";
  lock = reg_array.unique_lock();
  EXPECT_EQ(size, reg_array.size());
  for (const auto &reg : reg_array)
    EXPECT_EQ(0, reg.get<int>());
  reg_array[0].set(0x100000001ULL);
  EXPECT_EQ(1u, reg_array[0].get<unsigned int>());
}

TEST_F(StatefulTest, ResetPreservesNotifier) {
  size_t notifications = 0;
  size_t index = size;
  reg_array.register_notifier([&](size_t idx) {
    ++notifications;
    index = idx;
  });
  reg_array.reset_state();
  auto lock = reg_array.unique_lock();
  EXPECT_EQ(0u, notifications);
  reg_array[size - 1].set(42);
  EXPECT_EQ(1u, notifications);
  EXPECT_EQ(size - 1, index);
}

TEST_F(StatefulTest, ResetEmptyArray) {
  RegisterArray empty("empty", 1, 0, bitwidth);
  empty.reset_state();
  auto lock = empty.unique_lock();
  EXPECT_EQ(0u, empty.size());
  EXPECT_EQ(empty.begin(), empty.end());
}
