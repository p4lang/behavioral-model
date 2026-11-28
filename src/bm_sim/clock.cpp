// SPDX-FileCopyrightText: 2026 Bryan Richter
//
// SPDX-License-Identifier: Apache-2.0

#include <bm/bm_sim/clock.h>

#include <atomic>

namespace bm {

namespace {

class SystemClock final : public ClockIface {
 public:
  clock::time_point now() const override {
    return clock::now();
  }

  void wait_until(std::unique_lock<std::mutex> *lock,
                  std::condition_variable *cv,
                  clock::time_point tp) override {
    cv->wait_until(*lock, tp);
  }

  void wait(std::unique_lock<std::mutex> *lock,
            std::condition_variable *cv) override {
    cv->wait(*lock);
  }

  void notify_all(std::condition_variable *cv) override {
    cv->notify_all();
  }
};

SystemClock system_clock;

std::atomic<ClockIface *> installed_clock{&system_clock};

}  // namespace

ClockIface *
ClockIface::get() {
  return installed_clock.load();
}

void
ClockIface::set(ClockIface *clock) {
  installed_clock.store(clock ? clock : &system_clock);
}

void
ClockIface::Condvar::wait_until(std::unique_lock<std::mutex> *lock,
                                clock::time_point tp) {
  get()->wait_until(lock, &cv, tp);
}

void
ClockIface::Condvar::wait(std::unique_lock<std::mutex> *lock) {
  get()->wait(lock, &cv);
}

void
ClockIface::Condvar::notify_all() {
  get()->notify_all(&cv);
}

}  // namespace bm
