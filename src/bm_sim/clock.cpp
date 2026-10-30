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

}  // namespace bm
