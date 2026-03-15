/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
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

/*
 * Antonin Bas
 *
 */

#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

#include <PI/pi.h>

#include <memory>
#include <string>
#include <utility>  // std::move
#include <vector>

#include "google/rpc/code.pb.h"
#include "google/rpc/status.pb.h"

#include "report_error.h"
#include "statusor.h"

namespace pi {

namespace fe {

namespace proto {

using Code = ::google::rpc::Code;
using Status = ::google::rpc::Status;

namespace common {

using p4_id_t = uint32_t;

class SessionTemp;

// A mechanism for different sessions (main session, multicast session) to
// perform some low-level cleanup tasks in case of an unexpected error during an
// unexpected error (in the lower layers of the stack). For example, when using
// one-shot action selector programming for an indirect table, a single
// P4Runtime update may map to many PI calls. If one of these calls fail, it may
// be desirable to undo all previous PI calls. This isn't as powerful as the
// P4Runtime semantics (not implemented yet), but should be ok for simple things
// like action profile programming. If one of the rollback / cleanup operations
// fail, we return a (serious) INTERNAL error.
template <typename S, typename T>
class SessionCleanup {
 public:
  Status local_cleanup() {
    int error_cnt = 0;
    Status status;
    for (auto task_it = cleanup_tasks.rbegin();
         task_it != cleanup_tasks.rend();
         ++task_it) {
      status = (*task_it)->cleanup(*static_cast<S *>(this));
      if (IS_ERROR(status)) error_cnt++;
    }
    cleanup_tasks.clear();
    cleanup_scopes.clear();
    if (error_cnt == 0) RETURN_OK_STATUS();
    if (error_cnt == 1) return status;
    RETURN_ERROR_STATUS(
        Code::INTERNAL,
        "{} serious errors when encountered during cleanup; you may need to "
        "reboot the device", error_cnt);
  }

  void cleanup_scope_push() {
    cleanup_scopes.push_back(cleanup_tasks.size());
  }

  void cleanup_scope_pop() {
    cleanup_tasks.resize(cleanup_scopes.back());
    cleanup_scopes.pop_back();
  }

  T *cleanup_task_push(std::unique_ptr<T> task) {
    cleanup_tasks.push_back(std::move(task));
    return cleanup_tasks.back().get();
  }

  T *cleanup_task_back() {
    return cleanup_tasks.back().get();
  }

 protected:
  ~SessionCleanup() { }

 private:
  std::vector<std::unique_ptr<T> > cleanup_tasks;
  std::vector<size_t> cleanup_scopes;
};

struct LocalCleanupIface {
  virtual ~LocalCleanupIface() { }

  virtual Status cleanup(const SessionTemp &session) = 0;
  virtual void cancel() = 0;
};

// SessionTemp is used to manage a P4Runtime WriteRequest message. All
// operations in the message are executed as part of the same PI batch, the
// SessionTemp destructor will block until all operations have been completed in
// HW.
class SessionTemp final
    : public SessionCleanup<SessionTemp, LocalCleanupIface> {
 public:
  explicit SessionTemp(bool batch = false)
      : batch(batch) {
    pi_session_init(&sess);
    if (batch) pi_batch_begin(sess);
  }

  ~SessionTemp() {
    if (batch) pi_batch_end(sess, true  /* hw_sync */);
    pi_session_cleanup(sess);
  }

  pi_session_handle_t get() const { return sess; }

 private:
  pi_session_handle_t sess;
  bool batch;
};

// bytestring_p4rt_to_pi converts any valid P4Runtime bytestring to the format
// expected by PI. PI expects the length of the bytestring to be the same as the
// size of the P4 type, which may require the P4Runtime bytestring to be padded
// first.
StatusOr<std::string> bytestring_p4rt_to_pi(const std::string &str,
                                            size_t nbits);

// bytestring_pi_to_p4rt converts the PI bytestring to a canonical P4Runtime
// bytestring.
std::string bytestring_pi_to_p4rt(const std::string &str);
std::string bytestring_pi_to_p4rt(const char *, size_t n);

// Converts the given bytestring to the given `pi_port_t` and return OK if
// the bytestring fits into the port, or returns INVALID_ARGUMENT otherwise.
Status bytestring_to_pi_port(const std::string &str, pi_port_t* result);

// Converts the given `port` into a bytestring of `num_bytes` characters.
// If `num_bytes > sizeof(pi_port_t)`, the initial bytes are zero.
// If the given `port` has more than `num_bytes` significant bytes, only the
// `num_bytes` least significant bytes are captured.
std::string pi_port_to_bytestring(pi_port_t port, size_t num_bytes);

Code check_proto_bytestring(const std::string &str, size_t nbits);

bool check_prefix_trailing_zeros(const std::string &str, int pLen);

std::string range_default_lo(size_t nbits);
std::string range_default_hi(size_t nbits);

inline Status make_invalid_p4_id_status() {
  RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid P4 id");
}

}  // namespace common

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_COMMON_H_
