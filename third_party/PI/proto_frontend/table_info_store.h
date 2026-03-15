/* Copyright 2013-present Barefoot Networks, Inc.
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

#ifndef SRC_TABLE_INFO_STORE_H_
#define SRC_TABLE_INFO_STORE_H_

#include <PI/frontends/cpp/tables.h>
#include <PI/pi.h>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace pi {

namespace fe {

namespace proto {

class TableInfoStoreOne;

class TableInfoStore {
 public:
  // instead of storing proto data (RepeatedPtrField<p4::MatchKey>), we store
  // the PI match key representation. Using protobuf data as a key can become
  // somewhat nighmarish; in particular the order of match fields in the match
  // key should be able to change without impacting the hash or equality
  // operator.
  using MatchKey = pi::MatchKey;

  struct Data {
    Data(pi_entry_handle_t handle, uint64_t controller_metadata,
         const std::string &metadata, uint64_t idle_timeout_ns)
        : handle(handle), controller_metadata(controller_metadata),
          metadata(metadata), idle_timeout_ns(idle_timeout_ns) { }

    Data(pi_entry_handle_t handle, uint64_t controller_metadata,
         const std::string &metadata, uint64_t idle_timeout_ns,
         pi_indirect_handle_t oneshot_group_handle)
        : handle(handle), controller_metadata(controller_metadata),
          metadata(metadata), idle_timeout_ns(idle_timeout_ns),
          is_oneshot(true), oneshot_group_handle(oneshot_group_handle) { }

    const pi_entry_handle_t handle{0};
    uint64_t controller_metadata{0};
    std::string metadata;
    int64_t idle_timeout_ns{0};
    // wish I could use boost::optional here
    bool is_oneshot{false};
    pi_indirect_handle_t oneshot_group_handle{0};
  };

  using Mutex = std::mutex;
  using Lock = std::unique_lock<Mutex>;

  TableInfoStore();

  ~TableInfoStore();

  // Let the client be responsible for locking the table state if needed.
  Lock lock_table(pi_p4_id_t t_id) const;

  void add_table(pi_p4_id_t t_id);

  void add_entry(pi_p4_id_t t_id, const MatchKey &mk, const Data &data);

  void remove_entry(pi_p4_id_t t_id, const MatchKey &mk);

  Data *get_entry(pi_p4_id_t t_id, const MatchKey &mk) const;

  void reset();

 private:
  // TableInfoStoreOne includes a mutex, so we need a pointer
  std::unordered_map<pi_p4_id_t, std::unique_ptr<TableInfoStoreOne> > tables;
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_TABLE_INFO_STORE_H_
