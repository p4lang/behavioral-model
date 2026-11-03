/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef TESTS_UTILS_H_
#define TESTS_UTILS_H_

#include <bm/bm_sim/clock.h>
#include <bm/bm_sim/transport.h>

#include <algorithm>  // for std::copy, std::all_of
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <cassert>

class MemoryAccessor : public bm::TransportIface {
 public:
  enum class Status { CAN_READ, CAN_WRITE };
 public:
  MemoryAccessor(size_t max_size)
    : max_size(max_size), status(Status::CAN_WRITE) {
    buffer_.reserve(max_size);
  }

  int read(char *dst, size_t len) const {
    len = (len > max_size) ? max_size : len;
    std::unique_lock<std::mutex> lock(mutex);
    while (status != Status::CAN_READ) {
      can_read.wait(lock);
    }
    std::copy(buffer_.begin(), buffer_.begin() + len, dst);
    buffer_.clear();
    status = Status::CAN_WRITE;
    can_write.notify_one();
    return 0;
  }

  Status check_status() {
    std::unique_lock<std::mutex> lock(mutex);
    return status;
  }

 private:
  int open_() override {
    return 0;
  }

  int send_(const char *buffer, int len) const override {
    if (static_cast<size_t>(len) > max_size) return -1;
    std::unique_lock<std::mutex> lock(mutex);
    while (status != Status::CAN_WRITE) {
      can_write.wait(lock);
    }
    buffer_.insert(buffer_.end(), buffer, buffer + len);
    status = Status::CAN_READ;
    can_read.notify_one();
    return 0;
  }

  int send_(const std::string &msg) const override {
    (void)msg;
    // unused for learning
    assert(0);
    return 0;
  }

  int send_msgs_(const std::initializer_list<TransportIface::MsgBuf> &msgs)
      const override {
    size_t len = 0;
    for (const auto &msg : msgs) {
      len += msg.len;
    }
    if (len > max_size) return -1;
    std::unique_lock<std::mutex> lock(mutex);
    while (status != Status::CAN_WRITE) {
      can_write.wait(lock);
    }
    for (const auto &msg : msgs) {
      buffer_.insert(buffer_.end(), msg.buf, msg.buf + msg.len);
    }
    status = Status::CAN_READ;
    can_read.notify_one();
    return 0;
  }

  int send_msgs_(
      const std::initializer_list<std::string> &msgs) const override {
    (void)msgs;
    // unused for learning
    assert(0);
    return 0;
  }

 private:
  // dirty trick (mutable) to make sure that send() const is override
  mutable std::vector<char> buffer_;
  size_t max_size;
  mutable Status status;
  mutable std::mutex mutex;
  mutable std::condition_variable can_write;
  mutable std::condition_variable can_read;
};

// A clock that only moves when advance() is called, installed as the process
// clock for its lifetime.
class ManualClock : public bm::ClockIface {
 public:
  ManualClock() {
    bm::ClockIface::set(this);
  }

  ~ManualClock() {
    bm::ClockIface::set(nullptr);
  }

  clock::time_point now() const override {
    std::unique_lock<std::mutex> lock(mutex);
    return now_;
  }

  void wait_until(std::unique_lock<std::mutex> *lock,
                  std::condition_variable *cv,
                  clock::time_point tp) override {
    Waiter waiter{lock->mutex(), cv, tp};
    {
      std::unique_lock<std::mutex> clock_lock(mutex);
      if (now_ >= tp) return;
      waiters.push_back(&waiter);
    }
    waiters_changed.notify_all();
    cv->wait(*lock);
    {
      std::unique_lock<std::mutex> clock_lock(mutex);
      waiters.erase(std::find(waiters.begin(), waiters.end(), &waiter));
    }
    waiters_changed.notify_all();
  }

  // Wakes the waiters whose deadline the new time reaches. Their mutexes and
  // condition variables must stay alive until this returns.
  void advance(clock::duration d) {
    std::vector<Waiter> due;
    {
      std::unique_lock<std::mutex> lock(mutex);
      now_ += d;
      for (const Waiter *waiter : waiters)
        if (waiter->deadline <= now_) due.push_back(*waiter);
    }
    for (const Waiter &waiter : due) {
      // A waiter holds its mutex until it is blocked on its condvar.
      { std::unique_lock<std::mutex> lock(*waiter.mutex); }
      waiter.cv->notify_all();
    }
  }

  // Blocks until num_threads threads wait on this clock and none is due, i.e.
  // they have done all their work up to now(). False on timeout.
  bool wait_until_idle(size_t num_threads,
                       std::chrono::milliseconds timeout =
                           std::chrono::seconds(10)) {
    std::unique_lock<std::mutex> lock(mutex);
    return waiters_changed.wait_for(lock, timeout, [this, num_threads] {
      return waiters.size() == num_threads &&
          std::all_of(waiters.begin(), waiters.end(),
                      [this](const Waiter *w) { return w->deadline > now_; });
    });
  }

 private:
  struct Waiter {
    std::mutex *mutex;
    std::condition_variable *cv;
    clock::time_point deadline;
  };

  mutable std::mutex mutex;
  clock::time_point now_{std::chrono::hours(1)};
  std::vector<const Waiter *> waiters;
  std::condition_variable waiters_changed;
};

class CLIWrapperImp;

class CLIWrapper {
 public:
  CLIWrapper(int thrift_port, bool silent = false);
  ~CLIWrapper();

  void send_cmd(const std::string &cmd);

 private:
  std::unique_ptr<CLIWrapperImp> imp;
};

#endif  // TESTS_UTILS_H_
