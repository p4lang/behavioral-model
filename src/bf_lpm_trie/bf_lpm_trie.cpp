/*
 * Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
 * Copyright 2025 Modernization
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

 #ifndef BF_LPM_TRIE_HPP
 #define BF_LPM_TRIE_HPP
 
 #include <cstdint>
 #include <vector>
 #include <memory>
 #include <algorithm>
 #include <optional>
 #include <string_view>
 #include <cassert>
 
 namespace bf {
 
 using value_t = std::uintptr_t;
 using byte_t = std::uint8_t;
 
 class LpmTrie {
 private:
     class Node;
     
     struct Branch {
         byte_t value;
         std::unique_ptr<Node> next;
         
         Branch(byte_t v, std::unique_ptr<Node> n) : value(v), next(std::move(n)) {}
     };
     
     struct Prefix {
         uint8_t prefix_length;
         byte_t key;
         value_t value;
         
         Prefix(uint8_t len, byte_t k, value_t v) 
             : prefix_length(len), key(k), value(v) {}
         
         // Comparison operator for binary search
         bool operator<(const Prefix& other) const {
             if (prefix_length == other.prefix_length) {
                 return key < other.key;
             }
             return prefix_length > other.prefix_length;
         }
         
         bool operator==(const Prefix& other) const {
             return prefix_length == other.prefix_length && key == other.key;
         }
     };
     
     class Node {
     public:
         Node() = default;
         ~Node() = default;
         
         // Returns the next node for a given byte, or nullptr if not found
         Node* getNextNode(byte_t byte) const {
             auto it = std::lower_bound(branches.begin(), branches.end(), byte,
                 [](const Branch& b, byte_t byte) { return b.value < byte; });
                 
             if (it != branches.end() && it->value == byte) {
                 return it->next.get();
             }
             return nullptr;
         }
         
         // Sets the next node for a given byte
         void setNextNode(byte_t byte, std::unique_ptr<Node> next_node) {
             auto it = std::lower_bound(branches.begin(), branches.end(), byte,
                 [](const Branch& b, byte_t byte) { return b.value < byte; });
                 
             if (it != branches.end() && it->value == byte) {
                 it->next = std::move(next_node);
                 return;
             }
             
             branches.emplace(it, byte, std::move(next_node));
         }
         
         // Deletes a branch for a given byte, returns true if it was present
         bool deleteBranch(byte_t byte) {
             auto it = std::lower_bound(branches.begin(), branches.end(), byte,
                 [](const Branch& b, byte_t byte) { return b.value < byte; });
                 
             if (it != branches.end() && it->value == byte) {
                 branches.erase(it);
                 return true;
             }
             return false;
         }
         
         // Inserts a prefix, returns true if it was replacing an existing one
         bool insertPrefix(uint8_t prefix_length, byte_t key, value_t value) {
             Prefix prefix(prefix_length, key, value);
             
             auto it = std::lower_bound(prefixes.begin(), prefixes.end(), prefix);
             
             if (it != prefixes.end() && *it == prefix) {
                 it->value = value;
                 return true;
             }
             
             prefixes.emplace(it, prefix);
             return false;
         }
         
         // Gets a prefix, returns nullptr if not found
         const Prefix* getPrefix(uint8_t prefix_length, byte_t key) const {
             Prefix prefix(prefix_length, key, 0);
             
             auto it = std::lower_bound(prefixes.begin(), prefixes.end(), prefix);
             
             if (it != prefixes.end() && *it == prefix) {
                 return &(*it);
             }
             return nullptr;
         }
         
         // Gets the empty prefix (prefix_length == 0), returns nullptr if not found
         const Prefix* getEmptyPrefix() const {
             if (prefixes.empty()) return nullptr;
             
             const auto& p = prefixes.back();
             return (p.prefix_length == 0) ? &p : nullptr;
         }
         
         // Deletes a prefix, returns true if it was present
         bool deletePrefix(uint8_t prefix_length, byte_t key) {
             Prefix prefix(prefix_length, key, 0);
             
             auto it = std::lower_bound(prefixes.begin(), prefixes.end(), prefix);
             
             if (it != prefixes.end() && *it == prefix) {
                 prefixes.erase(it);
                 return true;
             }
             return false;
         }
         
         std::vector<Branch> branches;
         std::vector<Prefix> prefixes;
         Node* parent = nullptr;
         byte_t child_id = 0;
     };
     
     std::unique_ptr<Node> root;
     size_t key_width_bytes;
     bool release_memory;
     
 public:
     explicit LpmTrie(size_t key_width_bytes, bool auto_shrink = false)
         : root(std::make_unique<Node>()), 
           key_width_bytes(key_width_bytes),
           release_memory(auto_shrink) {
         assert(key_width_bytes <= 64);
     }
     
     ~LpmTrie() = default;
     
     // Disallow copying
     LpmTrie(const LpmTrie&) = delete;
     LpmTrie& operator=(const LpmTrie&) = delete;
     
     // Allow moving
     LpmTrie(LpmTrie&&) = default;
     LpmTrie& operator=(LpmTrie&&) = default;
     
     // Insert a prefix with a value
     void insert(std::string_view prefix, int prefix_length, value_t value) {
         Node* current_node = root.get();
         byte_t byte;
         
         while (prefix_length >= 8) {
             byte = static_cast<byte_t>(*prefix.data());
             Node* node = current_node->getNextNode(byte);
             
             if (!node) {
                 auto new_node = std::make_unique<Node>();
                 node = new_node.get();
                 node->parent = current_node;
                 node->child_id = byte;
                 current_node->setNextNode(byte, std::move(new_node));
             }
             
             prefix.remove_prefix(1);
             prefix_length -= 8;
             current_node = node;
         }
         
         byte_t key = prefix.empty() ? 0 : static_cast<byte_t>(*prefix.data()) >> (8 - prefix_length);
         current_node->insertPrefix(static_cast<uint8_t>(prefix_length), key, value);
     }
     
     // Retrieve a value for an exact prefix
     std::optional<value_t> retrieveValue(std::string_view prefix, int prefix_length) const {
         const Node* current_node = root.get();
         byte_t byte;
         
         while (prefix_length >= 8) {
             byte = static_cast<byte_t>(*prefix.data());
             const Node* node = current_node->getNextNode(byte);
             
             if (!node) return std::nullopt;
             
             prefix.remove_prefix(1);
             prefix_length -= 8;
             current_node = node;
         }
         
         byte_t key = prefix.empty() ? 0 : static_cast<byte_t>(*prefix.data()) >> (8 - prefix_length);
         
         const Prefix* p = current_node->getPrefix(prefix_length, key);
         if (!p) return std::nullopt;
         
         return p->value;
     }
     
     // Check if a prefix exists
     bool hasPrefix(std::string_view prefix, int prefix_length) const {
         return retrieveValue(prefix, prefix_length).has_value();
     }
     
     // Lookup a key, performing longest prefix match
     std::optional<value_t> lookup(std::string_view key) const {
         const Node* current_node = root.get();
         size_t key_width = std::min(key.size(), key_width_bytes);
         std::optional<value_t> result;
         
         while (current_node) {
             if (key_width == 0) {
                 const Prefix* p = current_node->getEmptyPrefix();
                 if (p) {
                     result = p->value;
                 }
                 break;
             }
             
             for (const auto& p : current_node->prefixes) {
                 byte_t byte = static_cast<byte_t>(*key.data()) >> (8 - p.prefix_length);
                 if (p.key == byte) {
                     result = p.value;
                     break;
                 }
             }
             
             current_node = current_node->getNextNode(static_cast<byte_t>(*key.data()));
             key.remove_prefix(1);
             key_width--;
         }
         
         return result;
     }
     
     // Delete a prefix
     bool deletePrefix(std::string_view prefix, int prefix_length) {
         Node* current_node = root.get();
         byte_t byte;
         
         while (prefix_length >= 8) {
             byte = static_cast<byte_t>(*prefix.data());
             Node* node = current_node->getNextNode(byte);
             
             if (!node) return false;
             
             prefix.remove_prefix(1);
             prefix_length -= 8;
             current_node = node;
         }
         
         byte_t key = prefix.empty() ? 0 : static_cast<byte_t>(*prefix.data()) >> (8 - prefix_length);
         
         if (!current_node->getPrefix(prefix_length, key)) return false;
         
         if (release_memory) {
             bool success = current_node->deletePrefix(prefix_length, key);
             assert(success);
             
             while (current_node->prefixes.empty() && current_node->branches.empty()) {
                 Node* tmp = current_node;
                 current_node = current_node->parent;
                 
                 if (!current_node) break;
                 
                 success = current_node->deleteBranch(tmp->child_id);
                 assert(success);
             }
         }
         
         return true;
     }
 };
 
 } // namespace bf
 
 #endif // BF_LPM_TRIE_HPP