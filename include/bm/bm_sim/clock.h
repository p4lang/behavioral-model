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

//! The time base of packet ingress timestamps, match entry ageing, and
//! periodic tasks. One instance serves the whole process; see get() and set().
class ClockIface {
 public:
  using clock = std::chrono::system_clock;

  //! A condition variable whose waits and notifications go through the
  //! installed clock.
  class Condvar {
   public:
    //! Waits until notified or until now() reaches \p tp, with \p lock held
    //! on entry and return. Like std::condition_variable, it may also return
    //! spuriously.
    void wait_until(std::unique_lock<std::mutex> *lock, clock::time_point tp);

    //! Waits until notified, with \p lock held on entry and return. It may
    //! also return spuriously.
    void wait(std::unique_lock<std::mutex> *lock);

    void notify_all();

   private:
    std::condition_variable cv;
  };

  virtual ~ClockIface() { }

  virtual clock::time_point now() const = 0;

  //! The installed clock, the system clock by default.
  static ClockIface *get();

  //! Installs \p clock, which must outlive its installation; nullptr
  //! reinstalls the system clock.
  static void set(ClockIface *clock);

 protected:
  //! See Condvar.
  virtual void wait_until(std::unique_lock<std::mutex> *lock,
                          std::condition_variable *cv,
                          clock::time_point tp) = 0;
  virtual void wait(std::unique_lock<std::mutex> *lock,
                    std::condition_variable *cv) = 0;
  virtual void notify_all(std::condition_variable *cv) = 0;
};

}  // namespace bm

#endif  // BM_BM_SIM_CLOCK_H_
