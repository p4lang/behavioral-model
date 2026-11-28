// SPDX-FileCopyrightText: 2026 Bryan Richter
//
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>

#include <bm/bm_sim/clock.h>

#include <chrono>
#include <mutex>
#include <thread>

#include "utils.h"

using bm::ClockIface;

// A thread woken through its Condvar is not idle until it waits again
TEST(ManualClock, NotifiedWaiterIsNotIdle) {
  ManualClock manual_clock;
  std::mutex mutex;
  ClockIface::Condvar condvar;
  int wakeups = 0;
  bool stop = false;

  std::thread waiter([&] {
    std::unique_lock<std::mutex> lock(mutex);
    int seen = 0;
    while (!stop) {
      while (wakeups == seen && !stop) condvar.wait(&lock);
      seen = wakeups;
    }
  });
  ASSERT_TRUE(manual_clock.wait_until_idle(1));

  {
    std::unique_lock<std::mutex> lock(mutex);
    wakeups++;
    condvar.notify_all();
    // Holding the mutex keeps the woken thread from waiting again.
    EXPECT_FALSE(manual_clock.wait_until_idle(1,
                                              std::chrono::milliseconds(100)));
  }
  EXPECT_TRUE(manual_clock.wait_until_idle(1));

  {
    std::unique_lock<std::mutex> lock(mutex);
    stop = true;
    condvar.notify_all();
  }
  waiter.join();
}
