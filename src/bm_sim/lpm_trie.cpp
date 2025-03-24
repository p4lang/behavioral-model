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

#include <bm/bm_sim/_assert.h>
#include <lpm_trie.h>

namespace bm {

struct Branch {
  byte_t v;
  std::unique_ptr<Node> next;
};

struct Prefix {
  uint8_t prefix_length;
  byte_t key;
  value_t value;
  Prefix(uint8_t prefix_length, byte_t key, value_t value)
      : prefix_length(prefix_length), key(key), value(value) {}
  bool operator<(const Prefix &other) const {
    return (prefix_length == other.prefix_length)
                ? (key < other.key)
                : (prefix_length > other.prefix_length);
  }
};

class Node {
 public:
  explicit Node(Node *parent = nullptr, byte_t child_id = 0)
      : parent(parent), child_id(child_id) {}

  Node *get_next_node(byte_t byte) const;

  void set_next_node(byte_t byte, std::unique_ptr<Node> next_node) {
    add_branch(byte, std::move(next_node));
  }

  Node *get_parent() const { return parent; }

  byte_t get_child_id() const { return child_id; }

  // Prefix

  bool get_prefix(uint8_t prefix_length, byte_t key, value_t *value);

  std::vector<Prefix> &get_prefixes() { return prefixes; }

  void insert_prefix(uint8_t prefix_length, byte_t key, value_t value);

  bool delete_prefix(uint8_t prefix_length, byte_t key);

  // Branch
  void add_branch(byte_t byte, std::unique_ptr<Node> nextNode);

  bool delete_branch(byte_t byte);

  bool get_empty_prefix(value_t *val);

  bool is_empty() const { return prefixes.empty() && branches.empty(); }

 private:
  std::vector<Branch> branches;
  std::vector<Prefix> prefixes;
  Node *parent;
  byte_t child_id;

  std::vector<Prefix>::iterator
  search_prefix_with_key(uint8_t prefix_length, byte_t key);
};


bool Node::get_empty_prefix(value_t *val) {
  if (prefixes.empty()) {
    return false;
  }
  Prefix &p = prefixes.back();
  if (p.prefix_length == 0) {
    *val = p.value;
    return true;
  }
  _BM_UNUSED(val);
  return false;
}

Node *Node::get_next_node(byte_t byte) const {
  auto it =
      std::lower_bound(branches.begin(), branches.end(), byte,
                       [](const Branch &b, byte_t val) { return b.v < val; });

  return (it != branches.end() && it->v == byte) ? it->next.get() : nullptr;
}

void Node::insert_prefix(uint8_t prefix_length, byte_t key, value_t value) {
  auto it = search_prefix_with_key(prefix_length, key);

  if (it != prefixes.end()) {
    it->value = value;
    return;
  }
  prefixes.emplace_back(prefix_length, key, value);
}

bool Node::get_prefix(uint8_t prefix_length, byte_t key, value_t *value) {
  auto it = search_prefix_with_key(prefix_length, key);
  if (it != prefixes.end()) {
    *value = it->value;
    return true;
  }
  return false;
}

bool Node::delete_prefix(uint8_t prefix_length, byte_t key) {
  auto it = search_prefix_with_key(prefix_length, key);
  if (it != prefixes.end()) {
    prefixes.erase(it);
    return true;
  }
  return false;
}

void Node::add_branch(byte_t byte, std::unique_ptr<Node> next_node) {
  auto it = std::lower_bound(
      branches.begin(), branches.end(), byte,
      [](const Branch &b, const byte_t &val) { return b.v < val; });
  if (it == branches.end() || it->v != byte) {
    branches.insert(it, {byte, std::move(next_node)});
  }
}

bool Node::delete_branch(byte_t byte) {
  auto it =
      std::lower_bound(branches.begin(), branches.end(), byte,
                       [](const Branch &b, byte_t val) { return b.v < val; });

  if (it != branches.end() && it->v == byte) {
    branches.erase(it);
    return true;
  }
  return false;
}

std::vector<Prefix>::iterator
Node::search_prefix_with_key(uint8_t prefix_length, byte_t key) {
  Prefix target = {prefix_length, key, 0};
  auto pred = [](const Prefix &p, const Prefix &target) { return p < target; };
  auto it = std::lower_bound(prefixes.begin(), prefixes.end(), target, pred);

  if (it != prefixes.end() && it->prefix_length == prefix_length &&
      it->key == key) {
    return it;
  }
  return prefixes.end();
}


LPMTrie::LPMTrie(std::size_t key_width_bytes) :
    key_width_bytes(key_width_bytes) {
    assert(key_width_bytes <= 64);
    root = std::make_unique<Node>();
  }

LPMTrie::LPMTrie(LPMTrie &&other) noexcept :
    key_width_bytes(other.key_width_bytes) {
  root.reset(other.root.release());
}

LPMTrie::~LPMTrie() {}

LPMTrie &LPMTrie::operator=(LPMTrie &&other) noexcept {
  key_width_bytes = other.key_width_bytes;
  root.reset(other.root.release());
  return *this;
}

void LPMTrie::insert(const std::string &prefix, int prefix_length,
                     value_t value) {
  Node *current_node = root.get();
  byte_t byte;
  for (int i = 0; prefix_length >= 8; ++i) {
    byte = static_cast<byte_t>(prefix[i]);
    Node *node = current_node->get_next_node(byte);

    if (!node) {
      auto new_node = std::make_unique<Node>(current_node, byte);
      node = new_node.get();
      current_node->set_next_node(byte, std::move(new_node));
    }

    prefix_length -= 8;
    current_node = node;
  }

  byte_t key = static_cast<byte_t>(prefix.back()) >> (8 - prefix_length);
  current_node->insert_prefix(prefix_length, key, value);
}

bool LPMTrie::retrieve_value(const std::string &prefix, int prefix_length,
                             value_t *value) const {
  Node *current_node = root.get();
  byte_t byte;

  for (int i = 0; prefix_length >= 8; ++i) {
    byte = static_cast<byte_t>(prefix[i]);
    current_node = current_node->get_next_node(byte);
    if (!current_node)
      return false;
    prefix_length -= 8;
  }

  byte_t key = static_cast<byte_t>(prefix.back()) >> (8 - prefix_length);
  return current_node->get_prefix(prefix_length, key, value);
}

bool LPMTrie::has_prefix(const std::string &prefix, int prefix_length) const {
  value_t value = 0;
  return retrieve_value(prefix, prefix_length, &value);
}

bool LPMTrie::remove(const std::string &prefix, int prefix_length) {
  Node *current_node = root.get();
  byte_t byte;

  for (int i = 0; prefix_length >= 8; ++i) {
    byte = static_cast<byte_t>(prefix[i]);
    current_node = current_node->get_next_node(byte);
    if (!current_node)
      return false;
    prefix_length -= 8;
  }

  byte_t key = static_cast<byte_t>(prefix.back()) >> (8 - prefix_length);
  if (!current_node->delete_prefix(prefix_length, key))
    return false;

  while (current_node->is_empty()) {
    Node *tmp = current_node;
    current_node = current_node->get_parent();
    if (!current_node)
      break;
    current_node->delete_branch(tmp->get_child_id());
  }

  return true;
}

bool LPMTrie::lookup(const std::string &key, value_t *value) const {
  Node *current_node = root.get();
  byte_t byte;
  size_t key_width = key_width_bytes;

  int key_idx = 0;
  while (current_node) {
    if (key_width == 0) {
      return current_node->get_empty_prefix(value);
    }

    for (auto &prefix : current_node->get_prefixes()) {
      byte = static_cast<byte_t>(key[key_idx]) >> (8 - prefix.prefix_length);
      if (byte == prefix.key) {
        *value = prefix.value;
        return true;
      }
    }
    current_node = current_node->get_next_node(key[key_idx]);
    key_width--;
    key_idx++;
  }

  return false;
}

void LPMTrie::clear() {
  root.reset(new Node());
}

}  // namespace bm
