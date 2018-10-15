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

#include <bm/bm_sim/periodic_task.h>
#include <bm/bm_sim/logger.h>

#include <string>
#include <iostream>

PeriodicTask::PeriodicTask(
    const std::string &name, std::function<void()> fn,
    std::chrono::milliseconds interval)
    : name(name), fn(fn), interval(interval),
      next(std::chrono::system_clock::now() + interval) {
  PeriodicTaskList::get_instance().register_task(this);
}

PeriodicTask::~PeriodicTask() {
  cancel();
}

void
PeriodicTask::cancel() {
  PeriodicTaskList::get_instance().unregister_task(this);
}

void
PeriodicTask::reset_next() {
  next = std::chrono::system_clock::now() + interval;
}

constexpr std::chrono::milliseconds PeriodicTaskList::default_timeout;

bool
PeriodicTaskList::contains_task(PeriodicTask *task) {
  std::lock_guard<std::mutex> lock(queue_mutex);

  TaskQueue tmp;
  bool contains = false;
  while (!task_queue.empty()) {
    if (task_queue.top() == task) {
      contains = true;
    }
    tmp.push(task_queue.top());
    task_queue.pop();
  }
  task_queue.swap(tmp);
  return contains;
}

bool
PeriodicTaskList::register_task(PeriodicTask *task) {
  if (contains_task(task)) {
    BMLOG_DEBUG("Warning: Task {} already exists in periodic task queue",
                task->name);
    return false;
  }

  std::lock_guard<std::mutex> lock(queue_mutex);
  task_queue.push(task);
  task->reset_next();
  cv.notify_all();
  return true;
}

bool
PeriodicTaskList::unregister_task(PeriodicTask *task) {
  std::lock_guard<std::mutex> lock(queue_mutex);

  TaskQueue tmp;
  bool removed = false;
  while (!task_queue.empty()) {
    if (task_queue.top() == task) {
      removed = true;
    } else {
      tmp.push(task_queue.top());
    }
    task_queue.pop();
  }
  task_queue.swap(tmp);

  cv.notify_all();
  if (!removed) {
    BMLOG_DEBUG("Warning: Task {} does not exist in periodic task queue",
                task->name);
    return false;
  }
  return true;
}

void
PeriodicTaskList::start() {
  exiting = false;
  running = true;
  periodic_thread = std::thread(&PeriodicTaskList::loop, this);
}

void
PeriodicTaskList::join() {
  if (!running) {
    BMLOG_DEBUG("Warning: Attempted to join non-running periodic thread");
    return;
  }
  exiting = true;
  periodic_thread.join();
  running = false;
}

void
PeriodicTaskList::loop() {
  while (!exiting) {
    std::unique_lock<std::mutex> lk(queue_mutex);
    std::chrono::system_clock::time_point next;
    if (!task_queue.empty()) {
      next = task_queue.top()->next;
    } else {
      next = std::chrono::system_clock::now() + default_timeout;
    }
    if (cv.wait_until(lk, next) == std::cv_status::timeout) {
      if (!task_queue.empty()) {
        auto task = task_queue.top();
        task_queue.pop();
        task->fn();
        task->reset_next();
        task_queue.push(task);
      }
    }
  }
}

PeriodicTaskList&
PeriodicTaskList::get_instance() {
    static PeriodicTaskList instance;
    return instance;
}

PeriodicTaskList::~PeriodicTaskList() {
    join();
}
