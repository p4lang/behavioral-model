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

//! Initializes and registers a task that is to be executed periodically
//! at a fixed interval. Task will execute during the lifetime of the object.
//! Make a member of an ActionPrimitive class to tie the execution to the
//! use of a specific primitive
//! @code
//! class MyExtern : public ActionPrimitive<> {
//!   MyExtern() : task("my_task",
//!                     std::bind(&MyExtern::periodic_fn, this),
//!                     std::chrono::seconds(1)) {}
//!
//!   void operator ()() {
//!     // This will execute when extern is called
//!   }
//!
//!   void periodic_fn() {
//!     // This will execute once a second
//!   }
//!
//!   PeriodicTask task;
//! }
//! @endcode
class PeriodicTask {
 public:
  PeriodicTask(const std::string &name,
               std::function<void()> fn,
               std::chrono::milliseconds interval);
  ~PeriodicTask();

  // Deleting copy-constructor and copy-assignment
  PeriodicTask(const PeriodicTask&) = delete;
  PeriodicTask& operator= (const PeriodicTask&) = delete;

  //! Executes the stored function and sets `next` to the next desired
  //! execution time
  void execute();

  const std::string name;
  const std::chrono::milliseconds interval;
  std::chrono::system_clock::time_point next;

 private:
  void reset_next();
  void cancel();

  const std::function<void()> fn;
};

//! Singleton which stores and executes periodic tasks.
//! Registration and unregistration are handled automatically
//! in the PeriodicTask constructor.
class PeriodicTaskList {
 public:
  static PeriodicTaskList &get_instance();

  // Returns true if task was successfully registered
  bool register_task(PeriodicTask *task);
  bool unregister_task(PeriodicTask *task);

  //! Starts the loop which executes the tasks in a new thread
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
  // The loop automatically cycles at least once in this interval
  static constexpr std::chrono::milliseconds kDefaultTimeout{1000};

  PeriodicTaskList() = default;
  ~PeriodicTaskList();

  bool contains_task(PeriodicTask *task);
  void loop();

  // The queue of PeriodicTasks, ordered by next execution time
  TaskQueue task_queue;

  std::thread periodic_thread;
  bool running;
  std::mutex queue_mutex;
  std::condition_variable cv;
};

}  // namespace bm

#endif  // BM_BM_SIM_PERIODIC_TASK_H_
