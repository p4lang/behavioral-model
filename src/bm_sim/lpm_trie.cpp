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

#include <lpm_trie.h>

#define _unused(x) ((void)(x))

namespace bm {

bool Node::get_empty_prefix(Prefix **prefix) {
  if (prefixes.is_empty()) {
    prefix = nullptr;
    return false;
  }
  Prefix *p = prefixes.back();
  if (p->prefix_length == 0) {
    *prefix = p;
    return true;
  }
  *prefix = nullptr;
  _unused(prefix);
  return false;
}

void BranchesVec::add_branch(byte_t byte, std::unique_ptr<Node> next_node) {
  auto it = std::lower_bound(
      branches.begin(), branches.end(), byte,
      [](const Branch &b, const byte_t &val) { return b.v < val; });
  if (it == branches.end() || it->v != byte) {
    branches.insert(it, {byte, std::move(next_node)});
  }
}

Node *BranchesVec::get_next_node(byte_t byte) const {
  auto it =
      std::lower_bound(branches.begin(), branches.end(), byte,
                       [](const Branch &b, byte_t val) { return b.v < val; });

  return (it != branches.end() && it->v == byte) ? it->next.get() : nullptr;
}

bool BranchesVec::delete_branch(byte_t byte) {
  auto it =
      std::lower_bound(branches.begin(), branches.end(), byte,
                       [](const Branch &b, byte_t val) { return b.v < val; });

  if (it != branches.end() && it->v == byte) {
    branches.erase(it);
    return true;
  }
  return false;
}

void PrefixesVec::insert_prefix(uint8_t prefix_length, byte_t key,
                                value_t value) {
  Prefix prefix = {prefix_length, key, value};
  auto it =
      std::lower_bound(prefixes.begin(), prefixes.end(), prefix,
                       [](const std::unique_ptr<Prefix> &p,
                          const Prefix &prefix) { return *p.get() < prefix; });

  if (it != prefixes.end() && (*it)->prefix_length == prefix_length &&
      (*it)->key == key) {
    (*it)->value = value;
    return;
  }
  prefixes.insert(it, std::make_unique<Prefix>(prefix));
}

Prefix *PrefixesVec::get_prefix(uint8_t prefix_length, byte_t key) {
  Prefix target = {prefix_length, key, 0};
  auto it =
      std::lower_bound(prefixes.begin(), prefixes.end(), target,
                       [](const std::unique_ptr<Prefix> &p,
                          const Prefix &prefix) { return *p.get() < prefix; });
  return (it != prefixes.end() && (*it)->prefix_length == prefix_length &&
          (*it)->key == key)
             ? it->get()
             : nullptr;
}

bool PrefixesVec::delete_prefix(uint8_t prefix_length, byte_t key) {
  Prefix target = {prefix_length, key, 0};
  auto it =
      std::lower_bound(prefixes.begin(), prefixes.end(), target,
                       [](const std::unique_ptr<Prefix> &p,
                          const Prefix &prefix) { return *p.get() < prefix; });
  if (it != prefixes.end() && (*it)->prefix_length == prefix_length &&
      (*it)->key == key) {
    prefixes.erase(it);
    return true;
  }
  return false;
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
  Prefix *p = current_node->get_prefix(prefix_length, key);
  if (!p)
    return false;

  *value = p->value;
  return true;
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
  bool found = false;
  Prefix *p = nullptr;

  int key_idx = 0;
  while (current_node) {
    if (key_width == 0) {
      current_node->get_empty_prefix(&p);
      if (p != nullptr) {
        *value = p->value;
        found = true;
      }
      break;
    }

    for (auto &prefix : current_node->get_prefixes().prefixes) {
      byte = static_cast<byte_t>(key[key_idx]) >> (8 - prefix->prefix_length);
      if (byte == prefix->key) {
        found = true;
        *value = prefix->value;
        break;
      }
    }
    current_node = current_node->get_next_node(key[key_idx]);
    key_width--;
    key_idx++;
  }

  return found;
}

}  // namespace bm

#undef _unused
