/* Copyright 2025 Contributors to the P4 Project
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

#ifndef BM_SIM_LPM_TRIE_H_
#define BM_SIM_LPM_TRIE_H_

#include <bm/bm_sim/bytecontainer.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace bm {

using value_t = std::uintptr_t;
using byte_t = unsigned char;

static_assert(sizeof(value_t) == sizeof(uintptr_t), "Invalid type sizes");

class Node;

class LPMTrie {
 public:
  explicit LPMTrie(std::size_t key_width_bytes);

  /* Copy constructor */
  LPMTrie(const LPMTrie &other) = delete;

  /* Move constructor */
  LPMTrie(LPMTrie &&other) noexcept;
  ~LPMTrie();

  /* Copy assignment operator */
  LPMTrie &operator=(const LPMTrie &other) = delete;

  /* Move assignment operator */
  LPMTrie &operator=(LPMTrie &&other) noexcept;

  void insert_prefix(const std::string &prefix, int prefix_length,
                     value_t value);
  void insert_prefix(const ByteContainer &prefix, int prefix_length,
                     value_t value);

  bool delete_prefix(const std::string &prefix, int prefix_length);
  bool delete_prefix(const ByteContainer &prefix, int prefix_length);

  bool has_prefix(const std::string &prefix, int prefix_length) const;
  bool has_prefix(const ByteContainer &prefix, int prefix_length) const;

  bool retrieve_value(const std::string &prefix, int prefix_length,
                      value_t *value) const;
  bool retrieve_value(const ByteContainer &prefix, int prefix_length,
                      value_t *value) const;
  bool lookup(const std::string &key, value_t *value) const;
  bool lookup(const ByteContainer &key, value_t *value) const;

  void clear();

 private:
  std::unique_ptr<Node> root;
  std::size_t key_width_bytes;
};

}  // namespace bm

#endif  // BM_SIM_LPM_TRIE_H_
