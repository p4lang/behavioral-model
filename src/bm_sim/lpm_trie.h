/* Copyright 2013-present Barefoot Networks, Inc.
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

#ifndef BM_SIM_LPM_TRIE_H_
#define BM_SIM_LPM_TRIE_H_

#include <bm/bm_sim/bytecontainer.h>

#include <algorithm>  // for std::swap
#include <utility>   // for std::swap
#include <string>
#include <memory>
#include <cassert>
#include <cstdint>
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

  void insert(const std::string &prefix, int prefix_length, value_t value);
  void insert_prefix(const ByteContainer &prefix, int prefix_length,
                     value_t value) {
    std::string prefix_str(prefix.data(), prefix.size());
    insert(prefix_str, prefix_length, value);
  }

  bool remove(const std::string &prefix, int prefix_length);
  bool delete_prefix(const ByteContainer &prefix, int prefix_length) {
    std::string prefix_str(prefix.data(), prefix.size());
    return remove(prefix_str, prefix_length);
  }
  bool has_prefix(const std::string &prefix, int prefix_length) const;
  bool has_prefix(const ByteContainer &prefix, int prefix_length) const {
    std::string prefix_str(prefix.data(), prefix.size());
    return has_prefix(prefix_str, prefix_length);
  }

  bool retrieve_value(const std::string &prefix, int prefix_length,
                      value_t *value) const;
  bool retrieve_value(const ByteContainer &prefix, int prefix_length,
                      value_t *value) const {
    std::string prefix_str(prefix.data(), prefix.size());
    return retrieve_value(prefix_str, prefix_length, value);
  }
  bool lookup(const std::string &key, value_t *value) const;
  bool lookup(const ByteContainer &key, value_t *value) const {
    std::string key_str(key.data(), key.size());
    return lookup(key_str, value);
  }

  void clear();

 private:
  std::unique_ptr<Node> root;
  std::size_t key_width_bytes;
};

}  // namespace bm

#endif  // BM_SIM_LPM_TRIE_H_
