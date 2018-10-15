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

#ifndef BM_BM_SIM_PERIODIC_TASK_H_
#define BM_BM_SIM_PERIODIC_TASK_H_

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <queue>
#include <chrono>
#include <functional>
#include <condition_variable>
#include <mutex>

namespace bm {

class PeriodicTask {
 public:
  PeriodicTask(const std::string &name,
               std::function<void()> fn,
               std::chrono::milliseconds interval);
  ~PeriodicTask();

  void reset_next();

  const std::string name;
  const std::function<void()> fn;
  const std::chrono::milliseconds interval;
  std::chrono::system_clock::time_point next;

 private:
  void cancel();
};

class PeriodicTaskList {
 public:
  static PeriodicTaskList &get_instance();

  bool register_task(PeriodicTask *task);
  bool unregister_task(PeriodicTask *task);

  void start();
  void join();

 private:
  class PeriodCompare {
   public:
    bool
    operator() (const PeriodicTask *lhs, const PeriodicTask *rhs) {
      return lhs->next > rhs->next;
    }
  };
  using TaskQueue = std::priority_queue<PeriodicTask*,
                                        std::vector<PeriodicTask*>,
                                        PeriodCompare>;

  static constexpr std::chrono::milliseconds default_timeout{1000};

  PeriodicTaskList() = default;
  ~PeriodicTaskList();

  bool contains_task(PeriodicTask *task);
  void loop();

  TaskQueue task_queue;

  std::thread periodic_thread;
  bool running;
  std::mutex queue_mutex;
  std::condition_variable cv;
};

}  // namespace bm

#endif  // BM_BM_SIM_PERIODIC_TASK_H_
