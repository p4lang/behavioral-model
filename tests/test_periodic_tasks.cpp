// Copyright 2018 Boon Thau Loo
// SPDX-FileCopyrightText: 2018 Boon Thau Loo
//
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>

#include <bm/bm_sim/periodic_task.h>

#include <chrono>
#include <functional>
#include <stdexcept>

#include "utils.h"

using namespace bm;

class PeriodicIncrementor {
 public:
  PeriodicIncrementor(const std::chrono::milliseconds &interval, int *i)
      : i(i), increment_task("increment",
                             std::bind(&PeriodicIncrementor::increment, this),
                             interval) {}

  void increment() {
    (*i)++;
  }
  int *i;

 private:
  PeriodicTask increment_task;
};

static constexpr int kPeriods = 5;

static constexpr std::chrono::milliseconds kInterval{100};

class PeriodicExtern : public ::testing::Test {
 protected:
  void TearDown() override {
    PeriodicTaskList::get_instance().join();
  }

  // Moves the clock forward step by step, waiting each time for the tasks due
  // by then to run.
  void advance(std::chrono::milliseconds step, int steps) {
    for (int k = 0; k < steps; k++) {
      manual_clock.advance(step);
      wait_for_tasks();
    }
  }

  void wait_for_tasks() {
    if (!manual_clock.wait_until_idle(1))
      throw std::runtime_error("periodic thread did not go idle");
  }

  ManualClock manual_clock;
};

// Tasks registered before the start of the thread execute on start
TEST_F(PeriodicExtern, PreStartRegistration) {
  int i = 0;
  PeriodicIncrementor incrementor(kInterval, &i);
  manual_clock.advance(kInterval * kPeriods);

  EXPECT_EQ(i, 0);

  PeriodicTaskList::get_instance().start();
  wait_for_tasks();

  EXPECT_EQ(i, 1);

  advance(kInterval, kPeriods);

  EXPECT_EQ(i, kPeriods + 1);
}

// Tasks registered after the start of the thread still execute
TEST_F(PeriodicExtern, PostStartRegistration) {
  int i = 0;
  PeriodicTaskList::get_instance().start();

  PeriodicIncrementor incrementor(kInterval, &i);
  advance(kInterval, kPeriods);

  EXPECT_EQ(i, kPeriods);
}

// Tasks stop executing when they go out of scope
TEST_F(PeriodicExtern, Unregistration) {
  int i = 0;
  PeriodicTaskList::get_instance().start();
  {
    PeriodicIncrementor incrementor(kInterval, &i);
    advance(kInterval, kPeriods);
  }
  advance(kInterval, kPeriods);

  EXPECT_EQ(i, kPeriods);
}

// Two tasks will be scheduled correctly
TEST_F(PeriodicExtern, MultipleTasks) {
  int i = 0;
  int j = 0;
  PeriodicTaskList::get_instance().start();
  {
    PeriodicIncrementor incrementor_1(kInterval, &i);
    PeriodicIncrementor incrementor_2(kInterval / 2, &j);
    advance(kInterval / 2, 2 * kPeriods);
  }

  EXPECT_EQ(i, kPeriods);
  EXPECT_EQ(j, 2 * kPeriods);
}
