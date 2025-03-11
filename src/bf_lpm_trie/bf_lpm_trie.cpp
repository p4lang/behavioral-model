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

#include <iostream> // for debugging, remove later
#include <iomanip> // for debugging, remove later
#define _unused(x) ((void)(x))

 // old above
 namespace bm {

 bool Node::getEmptyPrefix(Prefix **prefix) {
  printf("Node::getEmptyPrefix\n");
  if(prefixes.isEmpty()) {
    printf("prefixes Empty, false\n");
    prefix = nullptr;
    return false;
  }
  Prefix* p = prefixes.back();
  if(p->prefix_length == 0) {
    printf("prefix_length == 0, true\n");
    *prefix = p;
    printf("Address of prefix: %p\n", *prefix);
    return true;
  }
  *prefix = nullptr;
  _unused(prefix);
  printf("prefix_length != 0, false\n");
  return false;
}


// replace set_next_node
 void BranchesVec::addBranch(byte_t byte, std::unique_ptr<Node> nextNode) {
  auto it = std::lower_bound(branches.begin(), branches.end(), byte,
                             [](const Branch& b, const byte_t& val) { return b.v < val; });
  printf("BranchesVec::addBranch -> byte: %d\n", byte);
  if (it == branches.end() || it->v != byte) {
      branches.insert(it, {byte, std::move(nextNode)});
  }
}

Node* BranchesVec::getNextNode(byte_t byte) const {
  printf("BranchesVec::getNextNode -> byte: %d\n", byte);
  auto it = std::lower_bound(branches.begin(), branches.end(), byte,
                             [](const Branch& b, byte_t val) { return b.v < val; });

  return (it != branches.end() && it->v == byte) ? it->next.get() : nullptr;
}

bool BranchesVec::deleteBranch(byte_t byte) {
  printf("BranchesVec::deleteBranch -> byte: %d\n", byte);
  auto it = std::lower_bound(branches.begin(), branches.end(), byte,
                             [](const Branch& b, byte_t val) { return b.v < val; });

  if (it != branches.end() && it->v == byte) {
      branches.erase(it);
      return true;
  }
  return false;
}

// Hao: previously return 1 if was present, 0 otherwise, search usage
void PrefixesVec::insertPrefix(uint8_t prefix_length, byte_t key, value_t value) {
  printf("PrefixesVec::insertPrefix -> prefix_length: %d, key: %d, value: %d\n", prefix_length, key, value);
  Prefix prefix = {prefix_length, key, value};
  auto it = std::lower_bound(prefixes.begin(), prefixes.end(), prefix,
    [](const std::unique_ptr<Prefix>& p, const Prefix& prefix) { return *p.get() < prefix; });

  if(it!= prefixes.end() && (*it)->prefix_length == prefix_length && (*it)->key == key) {
    (*it)->value = value;
      return;
  }
  printf("Inserted\n");
  prefixes.insert(it, std::make_unique<Prefix>(prefix));
}

Prefix* PrefixesVec::getPrefix(uint8_t prefix_length, byte_t key) {
  printf("PrefixesVec::getPrefix -> prefix_length: %d, key: %d\n", prefix_length, key);
  Prefix target = {prefix_length, key, 0};
  auto it = std::lower_bound(prefixes.begin(), prefixes.end(), target,
    [](const std::unique_ptr<Prefix>& p, const Prefix& prefix) { return *p.get() < prefix; });
  return (it != prefixes.end() && (*it)->prefix_length == prefix_length && (*it)->key == key)
             ? it->get() : nullptr;
}

bool PrefixesVec::deletePrefix(uint8_t prefix_length, byte_t key) {
  printf("PrefixesVec::deletePrefix -> prefix_length: %d, key: %d\n", prefix_length, key);
  Prefix target = {prefix_length, key, 0};
  auto it = std::lower_bound(prefixes.begin(), prefixes.end(), target,
    [](const std::unique_ptr<Prefix>& p, const Prefix& prefix) { return *p.get() < prefix; });
  if (it != prefixes.end() && (*it)->prefix_length == prefix_length && (*it)->key == key) {
      prefixes.erase(it);
      return true;
  }
  return false;
}
void printPrefixes(const std::string& prefix) {
  printf("printPrefixes -> prefix with size %d:\n", prefix.size());
  for (unsigned char c : prefix) {  // Use `unsigned char` to avoid sign issues
    std::cout << std::hex << std::setw(2) << std::setfill('0') 
              << static_cast<int>(c) << " ";
}
std::cout << std::dec << std::endl; // Reset to decimal output
}
void BfLpmTrie::insert(const std::string& prefix, int prefix_length, value_t value) {
  // DEBUG!!
  printf("BfLpmTrie::insert -> prefix_length: %d, value: %d\n", prefix_length, value);
  printPrefixes(prefix);
  // END DEBUG

  Node* current_node = root.get();
  byte_t byte;
  for (int i = 0; prefix_length >= 8; ++i) {
      byte = static_cast<byte_t>(prefix[i]);
      Node* node = current_node->getNextNode(byte);

      if (!node) {
          auto newNode = std::make_unique<Node>(current_node, byte);
          node = newNode.get();
          current_node->setNextNode(byte, std::move(newNode));
      }

      prefix_length -= 8;
      current_node = node;
  }
  // previously: unsigned key = (unsigned) (unsigned char) *prefix >> (8 - prefix_length);
  byte_t key = static_cast<byte_t>(prefix.back()) >> (8 - prefix_length);
  printf("Key: %d\n", key);
  printf("prefix_length: %d\n", prefix_length);
  printf("prefix.front(): %d\n", static_cast<byte_t>(prefix.front()));
  current_node->insertPrefix(prefix_length, key, value);
}

bool BfLpmTrie::retrieveValue(const std::string& prefix, int prefix_length, value_t& value) const {
  printf("BfLpmTrie::retrieveValue -> prefix_length: %d\n", prefix_length);
  printPrefixes(prefix);
  Node* current_node = root.get();
  byte_t byte;

  for (int i = 0; prefix_length >= 8; ++i) {
      byte = static_cast<byte_t>(prefix[i]);
      current_node = current_node->getNextNode(byte);
      if (!current_node) return false;
      prefix_length -= 8;
  }

  byte_t key = static_cast<byte_t>(prefix.back()) >> (8 - prefix_length);
  Prefix* p = current_node->getPrefix(prefix_length, key);
  if (!p) return false;

  value = p->value;
  return true;
}

bool BfLpmTrie::hasPrefix(const std::string& prefix, int prefix_length) const {
  value_t value;
  return retrieveValue(prefix, prefix_length, value);
}

bool BfLpmTrie::remove(const std::string& prefix, int prefix_length){
  Node* current_node = root.get();
  byte_t byte;

  for (int i = 0; prefix_length >= 8; ++i) {
      byte = static_cast<byte_t>(prefix[i]);
      current_node = current_node->getNextNode(byte);
      if (!current_node) return false;
      prefix_length -= 8;
  }

  byte_t key = static_cast<byte_t>(prefix.back()) >> (8 - prefix_length);
  if (!current_node->deletePrefix(prefix_length, key)) return false;

  // release_memory should be used here, needed??
  while (current_node->isEmpty()) {
      Node* tmp = current_node;
      current_node = current_node->getParent();
      if (!current_node) break;
      current_node->deleteBranch(tmp->getChildID());
  }

  return true;
}


// Hao: cannot understand this. does it walk the trie????
bool BfLpmTrie::lookup(const std::string& key, value_t& value) const {
  printf("BfLpmTrie::lookup value:%d\nkey:\n", value);
  printPrefixes(key);

  Node* current_node = root.get();
  byte_t byte;
  size_t key_width = key_width_bytes;
  bool found = false;
  Prefix* p = nullptr;
  // originally it just add the pointer, check if this works. 
  int key_idx = 0;
  while(current_node){
    if(key_width == 0){
      current_node->getEmptyPrefix(&p);
      if(p!=nullptr){
        printf("found\n");
        value = p->value;
        found = true;
      }else printf("not found\n");
      break;
    }

    for(auto& prefix : current_node->getPrefixes().prefixes){
      byte = static_cast<byte_t>(key[key_idx]) >> (8 - prefix->prefix_length);
      printf("byte: %d\n", byte);
      printf("prefix->key: %d\n", prefix->key);
      if(byte == prefix->key){
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

}  // namespace bm

#undef _unused