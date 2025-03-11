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

#include <bf_lpm_trie/bf_lpm_trie.h>

#define _unused(x) ((void)(x))

namespace bm {

bool Node::getEmptyPrefix(Prefix **prefix) {
  if (prefixes.isEmpty()) {
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

void BranchesVec::addBranch(byte_t byte, std::unique_ptr<Node> nextNode) {
  auto it = std::lower_bound(
      branches.begin(), branches.end(), byte,
      [](const Branch &b, const byte_t &val) { return b.v < val; });
  if (it == branches.end() || it->v != byte) {
    branches.insert(it, {byte, std::move(nextNode)});
  }
}

Node *BranchesVec::getNextNode(byte_t byte) const {
  auto it =
      std::lower_bound(branches.begin(), branches.end(), byte,
                       [](const Branch &b, byte_t val) { return b.v < val; });

  return (it != branches.end() && it->v == byte) ? it->next.get() : nullptr;
}

bool BranchesVec::deleteBranch(byte_t byte) {
  auto it =
      std::lower_bound(branches.begin(), branches.end(), byte,
                       [](const Branch &b, byte_t val) { return b.v < val; });

  if (it != branches.end() && it->v == byte) {
    branches.erase(it);
    return true;
  }
  return false;
}

void PrefixesVec::insertPrefix(uint8_t prefix_length, byte_t key,
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

Prefix *PrefixesVec::getPrefix(uint8_t prefix_length, byte_t key) {
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

bool PrefixesVec::deletePrefix(uint8_t prefix_length, byte_t key) {
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

void BfLpmTrie::insert(const std::string &prefix, int prefix_length,
                       value_t value) {
  Node *current_node = root.get();
  byte_t byte;
  for (int i = 0; prefix_length >= 8; ++i) {
    byte = static_cast<byte_t>(prefix[i]);
    Node *node = current_node->getNextNode(byte);

    if (!node) {
      auto newNode = std::make_unique<Node>(current_node, byte);
      node = newNode.get();
      current_node->setNextNode(byte, std::move(newNode));
    }

    prefix_length -= 8;
    current_node = node;
  }

  byte_t key = static_cast<byte_t>(prefix.back()) >> (8 - prefix_length);
  current_node->insertPrefix(prefix_length, key, value);
}

bool BfLpmTrie::retrieveValue(const std::string &prefix, int prefix_length,
                              value_t &value) const {
  Node *current_node = root.get();
  byte_t byte;

  for (int i = 0; prefix_length >= 8; ++i) {
    byte = static_cast<byte_t>(prefix[i]);
    current_node = current_node->getNextNode(byte);
    if (!current_node)
      return false;
    prefix_length -= 8;
  }

  byte_t key = static_cast<byte_t>(prefix.back()) >> (8 - prefix_length);
  Prefix *p = current_node->getPrefix(prefix_length, key);
  if (!p)
    return false;

  value = p->value;
  return true;
}

bool BfLpmTrie::hasPrefix(const std::string &prefix, int prefix_length) const {
  value_t value;
  return retrieveValue(prefix, prefix_length, value);
}

bool BfLpmTrie::remove(const std::string &prefix, int prefix_length) {
  Node *current_node = root.get();
  byte_t byte;

  for (int i = 0; prefix_length >= 8; ++i) {
    byte = static_cast<byte_t>(prefix[i]);
    current_node = current_node->getNextNode(byte);
    if (!current_node)
      return false;
    prefix_length -= 8;
  }

  byte_t key = static_cast<byte_t>(prefix.back()) >> (8 - prefix_length);
  if (!current_node->deletePrefix(prefix_length, key))
    return false;

  while (current_node->isEmpty()) {
    Node *tmp = current_node;
    current_node = current_node->getParent();
    if (!current_node)
      break;
    current_node->deleteBranch(tmp->getChildID());
  }

  return true;
}

bool BfLpmTrie::lookup(const std::string &key, value_t &value) const {
  Node *current_node = root.get();
  byte_t byte;
  size_t key_width = key_width_bytes;
  bool found = false;
  Prefix *p = nullptr;

  int key_idx = 0;
  while (current_node) {
    if (key_width == 0) {
      current_node->getEmptyPrefix(&p);
      if (p != nullptr) {
        value = p->value;
        found = true;
      }
      break;
    }

    for (auto &prefix : current_node->getPrefixes().prefixes) {
      byte = static_cast<byte_t>(key[key_idx]) >> (8 - prefix->prefix_length);
      if (byte == prefix->key) {
        found = true;
        value = prefix->value;
        break;
      }
    }
    current_node = current_node->getNextNode(key[key_idx]);
    key_width--;
    key_idx++;
  }

  return found;
}

} // namespace bm

#undef _unused