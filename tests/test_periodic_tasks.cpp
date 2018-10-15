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

#include <gtest/gtest.h>

#include <bm/bm_sim/periodic_task.h>

#include <chrono>
#include <functional>

using namespace bm;

class PeriodicIncrementor {
 public:
  PeriodicIncrementor(const std::chrono::milliseconds &interval)
      : increment_task("increment",
                       std::bind(&PeriodicIncrementor::increment, this),
                       interval) {}
  void increment() {
    i++;
  }
  int i{0};

 private:
  PeriodicTask increment_task;
};

static constexpr int kSleepTimeMs = 500;
static constexpr int kPeriods = 5;

static constexpr std::chrono::milliseconds kInterval{kSleepTimeMs / kPeriods};
static constexpr std::chrono::milliseconds kSleepTime{kSleepTimeMs};

TEST(PeriodicExtern, PreStartRegistration) {
  PeriodicIncrementor incrementor(kInterval);
  std::this_thread::sleep_for(kSleepTime);

  ASSERT_EQ(incrementor.i, 0);

  PeriodicTaskList::get_instance().start();
  std::this_thread::sleep_for(kSleepTime);
  PeriodicTaskList::get_instance().join();

  ASSERT_GE(incrementor.i, kPeriods - 1);
  ASSERT_LE(incrementor.i, kPeriods + 1);
}

TEST(PeriodicExtern, PostStartRegistration) {
  PeriodicTaskList::get_instance().start();

  PeriodicIncrementor incrementor(kInterval);

  std::this_thread::sleep_for(kSleepTime);
  PeriodicTaskList::get_instance().join();

  ASSERT_GE(incrementor.i, kPeriods - 1);
  ASSERT_LE(incrementor.i, kPeriods + 1);
}

TEST(PeriodicExtern, Unregistration) {
  int i;
  PeriodicTaskList::get_instance().start();
  {
    PeriodicIncrementor incrementor(kInterval);
    std::this_thread::sleep_for(kSleepTime);
    i = incrementor.i;
  }
  std::this_thread::sleep_for(kSleepTime);

  ASSERT_GE(i, kPeriods - 1);
  ASSERT_LE(i, kPeriods + 1);
}

