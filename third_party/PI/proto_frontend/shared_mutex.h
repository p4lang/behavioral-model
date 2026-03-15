/* Copyright 2020 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
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

#ifndef PROTO_SERVER_SHARED_MUTEX_H_
#define PROTO_SERVER_SHARED_MUTEX_H_

#ifdef USE_ABSL
#include "absl/synchronization/mutex.h"
#else
// shared mutex not available in C++11
#include <boost/thread/shared_mutex.hpp>
#endif

namespace pi {

namespace server {

#ifdef USE_ABSL
// The absl versions delete the default move constructor and default move
// assignment operator, so I define my own versions here.
class SCOPED_LOCKABLE ReaderMutexLock {
 public:
  explicit ReaderMutexLock(absl::Mutex *mu) SHARED_LOCK_FUNCTION(mu)
      :  mu_(mu) {
    mu->ReaderLock();
  }

  ReaderMutexLock(const ReaderMutexLock&) = delete;
  ReaderMutexLock(ReaderMutexLock&&) = default;
  ReaderMutexLock& operator=(const ReaderMutexLock&) = delete;
  ReaderMutexLock& operator=(ReaderMutexLock&&) = default;

  ~ReaderMutexLock() UNLOCK_FUNCTION() {
    this->mu_->ReaderUnlock();
  }

 private:
  absl::Mutex *const mu_;
};

class SCOPED_LOCKABLE WriterMutexLock {
 public:
  explicit WriterMutexLock(absl::Mutex *mu) EXCLUSIVE_LOCK_FUNCTION(mu)
      : mu_(mu) {
    mu->WriterLock();
  }

  WriterMutexLock(const WriterMutexLock&) = delete;
  WriterMutexLock(WriterMutexLock&&) = default;
  WriterMutexLock& operator=(const WriterMutexLock&) = delete;
  WriterMutexLock& operator=(WriterMutexLock&&) = default;

  ~WriterMutexLock() UNLOCK_FUNCTION() {
    this->mu_->WriterUnlock();
  }

 private:
  absl::Mutex *const mu_;
};

using SharedMutex = absl::Mutex;
using SharedLock = ReaderMutexLock;
using UniqueLock = WriterMutexLock;

// NOLINTNEXTLINE(runtime/references)
inline SharedLock shared_lock(SharedMutex &m) { return SharedLock(&m); }
// NOLINTNEXTLINE(runtime/references)
inline UniqueLock unique_lock(SharedMutex &m) { return UniqueLock(&m); }
#else
using SharedMutex = boost::shared_mutex;
using SharedLock = boost::shared_lock<SharedMutex>;
using UniqueLock = boost::unique_lock<SharedMutex>;

// NOLINTNEXTLINE(runtime/references)
inline SharedLock shared_lock(SharedMutex &m) { return SharedLock(m); }
// NOLINTNEXTLINE(runtime/references)
inline UniqueLock unique_lock(SharedMutex &m) { return UniqueLock(m); }
#endif

}  // namespace server

}  // namespace pi

#endif  // PROTO_SERVER_SHARED_MUTEX_H_
