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

#include <PI/frontends/cpp/tables.h>
#include <PI/pi.h>

#include <memory>
#include <sstream>
#include <unordered_map>

#include "table_info_store.h"

namespace pi {

namespace fe {

namespace proto {

using MatchKey = TableInfoStore::MatchKey;
using Data = TableInfoStore::Data;
using Mutex = TableInfoStore::Mutex;
using Lock = TableInfoStore::Lock;

class TableInfoStoreOne {
 public:
  void add_entry(const MatchKey &mk, const Data &data) {
    data_map.emplace(mk, data);
  }

  void remove_entry(const MatchKey &mk) {
    data_map.erase(mk);
  }

  Data *get_entry(const MatchKey &mk) {
    auto it = data_map.find(mk);
    return (it == data_map.end()) ? nullptr : &it->second;
  }

  Lock lock() const { return Lock(mutex); }

 private:
  mutable Mutex mutex{};
  std::unordered_map<MatchKey, Data, pi::MatchKeyHash, pi::MatchKeyEq>
  data_map{};
};

TableInfoStore::TableInfoStore() = default;
TableInfoStore::~TableInfoStore() = default;

Lock
TableInfoStore::lock_table(pi_p4_id_t t_id) const {
  auto &table = tables.at(t_id);
  return table->lock();
}

void
TableInfoStore::add_table(pi_p4_id_t t_id) {
  tables.emplace(
      t_id, std::unique_ptr<TableInfoStoreOne>(new TableInfoStoreOne()));
}

void
TableInfoStore::add_entry(pi_p4_id_t t_id, const MatchKey &mk,
                          const Data &data) {
  auto &table = tables.at(t_id);
  table->add_entry(mk, data);
}

void
TableInfoStore::remove_entry(pi_p4_id_t t_id, const MatchKey &mk) {
  auto &table = tables.at(t_id);
  table->remove_entry(mk);
}

Data *
TableInfoStore::get_entry(pi_p4_id_t t_id, const MatchKey &mk) const {
  auto &table = tables.at(t_id);
  return table->get_entry(mk);
}

void
TableInfoStore::reset() {
  tables.clear();
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
