/*
 * SPDX-FileCopyrightText: 2026 Bryan Richter
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! @file clock.h

#ifndef BM_BM_SIM_CLOCK_H_
#define BM_BM_SIM_CLOCK_H_

#include <chrono>
#include <condition_variable>
#include <mutex>

namespace bm {

//! The time base of packet ingress timestamps and match entry ageing. One
//! instance serves the whole process; see get() and set().
class ClockIface {
 public:
  using clock = std::chrono::system_clock;

  virtual ~ClockIface() { }

  virtual clock::time_point now() const = 0;

  //! Waits on \p cv, which \p lock must be held for, until \p cv is notified
  //! or now() reaches \p tp. Like std::condition_variable::wait_until, it may
  //! also return spuriously.
  virtual void wait_until(std::unique_lock<std::mutex> *lock,
                          std::condition_variable *cv,
                          clock::time_point tp) = 0;

  //! The installed clock, the system clock by default.
  static ClockIface *get();

  //! Installs \p clock, which must outlive its installation; nullptr
  //! reinstalls the system clock.
  static void set(ClockIface *clock);
};

}  // namespace bm

#endif  // BM_BM_SIM_CLOCK_H_
