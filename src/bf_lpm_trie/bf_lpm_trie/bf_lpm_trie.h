/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
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

#ifndef _BF_LPM_TRIE_H
#define _BF_LPM_TRIE_H

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace bm {
// Hao: uintptr_t is a c type, equivalent to unsigned long, but need to make
// sure
typedef std::uintptr_t value_t;
typedef unsigned char byte_t;

class Node;

struct Branch {
  byte_t v;
  std::unique_ptr<Node> next;
};

class BranchesVec {
public:
  void add_branch(byte_t byte, std::unique_ptr<Node> nextNode);
  Node *get_next_node(byte_t byte) const;
  bool delete_branch(byte_t byte);
  bool is_empty() const { return branches.empty(); }

private:
  std::vector<Branch> branches;
};

struct Prefix {
  uint8_t prefix_length;
  byte_t key;
  value_t value;
  // replace prefix_cmp, order from long to short
  bool operator<(const Prefix &other) const {
    return (prefix_length == other.prefix_length)
               ? (key < other.key)
               : (prefix_length > other.prefix_length);
  }
};

class PrefixesVec {
public:
  void insert_prefix(uint8_t prefix_length, byte_t key, value_t value);
  Prefix *get_prefix(uint8_t prefix_length, byte_t key);
  bool delete_prefix(uint8_t prefix_length, byte_t key);

  inline bool is_empty() const { return prefixes.empty(); }
  inline Prefix *back() { return prefixes.back().get(); }

  std::vector<std::unique_ptr<Prefix>> prefixes;
};

class Node {
public:
  explicit Node(Node *parent = nullptr, byte_t child_id = 0)
      : parent(parent), child_id(child_id) {}

  Node *get_next_node(byte_t byte) const { return branches.get_next_node(byte); }

  void set_next_node(byte_t byte, std::unique_ptr<Node> next_node) {
    branches.add_branch(byte, std::move(next_node));
  }

  Prefix *get_prefix(uint8_t prefix_length, byte_t key) {
    return prefixes.get_prefix(prefix_length, key);
  }

  PrefixesVec &get_prefixes() { return prefixes; }

  bool insert_prefix(uint8_t prefix_length, byte_t key, value_t value) {
    prefixes.insert_prefix(prefix_length, key, value);
    return true;
  }

  bool delete_prefix(uint8_t prefix_length, byte_t key) {
    return prefixes.delete_prefix(prefix_length, key);
  }

  bool is_empty() const { return prefixes.is_empty() && branches.is_empty(); }

  void delete_branch(byte_t byte) { branches.delete_branch(byte); }

  bool get_empty_prefix(Prefix **prefix);

  Node *get_parent() const { return parent; }

  byte_t get_child_id() const { return child_id; }

private:
  BranchesVec branches;
  PrefixesVec prefixes;
  Node *parent;
  byte_t child_id;
};

class BfLpmTrie {
public:
  BfLpmTrie(std::size_t key_width_bytes) : key_width_bytes(key_width_bytes) {
    assert(key_width_bytes <= 64);
    root = std::make_unique<Node>();
  }

  void insert(const std::string &prefix, int prefix_length, value_t value);
  bool retrieve_value(const std::string &prefix, int prefix_length,
                     value_t &value) const;
  bool has_prefix(const std::string &prefix, int prefix_length) const;
  bool remove(const std::string &prefix, int prefix_length);
  bool lookup(const std::string &key, value_t &value) const;

private:
  std::unique_ptr<Node> root;
  std::size_t key_width_bytes;
  // Hao: used to free up memo for trie deletion, not needed, remove
  // bool release_memory;
};

} // namespace bm
#endif
