/* Copyright 2019-present Barefoot Networks, Inc.
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
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef SRC_ACCESS_ARBITRATION_H_
#define SRC_ACCESS_ARBITRATION_H_

#include <PI/p4info.h>
#include <PI/proto/util.h>

#include <condition_variable>
#include <mutex>
#include <set>
#include <utility>

#include "common.h"

namespace p4 {
namespace v1 {
class WriteRequest;
}  // namespace v1
}  // namespace p4

namespace pi {

namespace fe {

namespace proto {

// Arbitrates access between different concurrent RPCs. There are 4 different
// levels of access:
//   * UpdateAccess: exclusive, no concurrent access possible
//   * WriteAccess: exclusive access to a specific set of P4Info objects
//   * ReadAccess: shared access to the entire set of P4Info objects; other
//     ReadAccess instances can exist concurrently, and so can NoWriteAccess
//     instances, but it is not possible to have a concurrent WriteAccess
//     instance
//   * NoWriteAccess: access to a specific P4Info object that tolerates
//     concurrent ReadAccess instances, but not concurrent WriteAccess /
//     NoWriteAccess instances with an overlapping subset of P4Info objects
class AccessArbitration {
 public:
  struct skip_if_update_t { };

  // for access methods that support a skip_if_update_t overload, do not block
  // if there is an ongoing update, instead returns an Access instance that
  // evaluates to false (returns false when calling has_access).
  static constexpr skip_if_update_t skip_if_update{};

  struct one_of_t { };
  static constexpr one_of_t one_of{};

  class Access {
   public:
    bool has_access() const noexcept {
      return arbitrator != nullptr;
    }

    explicit operator bool() const noexcept {
      return has_access();
    }

    Access(const Access &) = delete;
    Access &operator=(const Access &) = delete;
    Access(Access &&) = delete;
    Access &operator=(Access &&) = delete;

   protected:
    explicit Access(AccessArbitration *arbitrator);
    ~Access();

    AccessArbitration *arbitrator;
  };

  class WriteAccess : public Access {
   public:
    template <typename ...Args>
    explicit WriteAccess(AccessArbitration *arbitrator, Args &&...args)
        : Access(arbitrator) {
      arbitrator->write_access(this, std::forward<Args>(args)...);
    }

    ~WriteAccess();

   private:
    friend class AccessArbitration;
    std::set<common::p4_id_t> p4_ids;
  };

  class ReadAccess : public Access {
   public:
    template <typename ...Args>
    explicit ReadAccess(AccessArbitration *arbitrator, Args &&...args)
        : Access(arbitrator) {
      arbitrator->read_access(this, std::forward<Args>(args)...);
    }

    ~ReadAccess();

   private:
    friend class AccessArbitration;
  };

  class NoWriteAccess : public Access {
   public:
    template <typename ...Args>
    explicit NoWriteAccess(AccessArbitration *arbitrator, Args &&...args)
        : Access(arbitrator) {
      arbitrator->no_write_access(this, std::forward<Args>(args)...);
    }

    ~NoWriteAccess();

    common::p4_id_t p4_id() const { return p4_id_; }

   private:
    friend class AccessArbitration;
    common::p4_id_t p4_id_{PI_INVALID_ID};
  };

  class UpdateAccess : public Access {
   public:
    template <typename ...Args>
    explicit UpdateAccess(AccessArbitration *arbitrator, Args &&...args)
        : Access(arbitrator) {
      arbitrator->update_access(this, std::forward<Args>(args)...);
    }

    ~UpdateAccess();

   private:
    friend class AccessArbitration;
  };

  // TODO(antonin): we need a much more efficient data structure for this
  // critical code, the set will perform memory allocation for every insert and
  // we should try to use contiguous memory to perform set intersection
  // efficiently.
  using P4IdSet = std::set<common::p4_id_t>;

 private:
  void write_access(WriteAccess *access,
                    const ::p4::v1::WriteRequest &request,
                    const pi_p4info_t *p4info);
  void write_access(WriteAccess *access, common::p4_id_t p4_id);

  void read_access(ReadAccess *access);

  void no_write_access(NoWriteAccess *access, common::p4_id_t p4_id);
  void no_write_access(NoWriteAccess *access,
                       common::p4_id_t p4_id,
                       skip_if_update_t);
  // The one_of_t overload gains access to a single object in the set, and
  // updates the set before returning (i.e. removes element to which we gained
  // access).
  // TODO(antonin): add "all_of_t" overloads if needed
  void no_write_access(NoWriteAccess *access,
                       P4IdSet *p4_ids,
                       one_of_t);
  void no_write_access(NoWriteAccess *access,
                       P4IdSet *p4_ids,
                       one_of_t,
                       skip_if_update_t);

  void update_access(UpdateAccess *access);

  void release_write_access(const WriteAccess &access);

  void release_no_write_access(const NoWriteAccess &access);

  void release_read_access();

  void release_update_access();

  bool validate_state();

  mutable std::mutex mutex;
  mutable std::condition_variable cv;
  P4IdSet p4_ids_busy;
  int read_cnt{0};
  int write_cnt{0};
  int update_cnt{0};
  int no_write_cnt{0};
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_ACCESS_ARBITRATION_H_
