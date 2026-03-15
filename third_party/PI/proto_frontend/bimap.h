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

#ifndef SRC_BIMAP_H_
#define SRC_BIMAP_H_

#include <unordered_map>

namespace pi {

namespace fe {

namespace proto {

template <typename T1, typename T2>
class BiMap {
 public:
  void add_mapping_1_2(const T1 &t1, const T2 &t2) {
    map_1_2.emplace(t1, t2);
    map_2_1.emplace(t2, t1);
  }

  // returns nullptr if no matching entry
  const T2 *get_from_1(const T1 &t1) const {
    auto it = map_1_2.find(t1);
    return (it == map_1_2.end()) ? nullptr : &it->second;
  }

  const T1 *get_from_2(const T2 &t2) const {
    auto it = map_2_1.find(t2);
    return (it == map_2_1.end()) ? nullptr : &it->second;
  }

  void remove_from_1(const T1 &t1) {
    map_1_2.erase(t1);
  }

  void remove_from_2(const T2 &t2) {
    map_2_1.erase(t2);
  }

  bool empty() const { return map_1_2.empty(); }

 private:
  std::unordered_map<T1, T2> map_1_2{};
  std::unordered_map<T2, T1> map_2_1{};
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_BIMAP_H_
