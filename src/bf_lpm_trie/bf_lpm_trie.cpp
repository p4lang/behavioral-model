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

#include "bf_lpm_trie.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>
#include <iostream>

namespace bm {

// Use byte_t for clarity when handling individual bytes
using byte_t = uint8_t;

// Forward declarations
struct Node;

/**
 * Represents a branch in the trie, pointing to a child node
 */
struct Branch {
  byte_t value;               // The byte value for this branch
  std::unique_ptr<Node> next; // Pointer to child node

  // Constructor transfers ownership of the child node
  Branch(byte_t v, std::unique_ptr<Node> n)
      : value(v), next(std::move(n)) {}
};

/**
 * Represents a prefix entry stored in a trie node
 */
struct Prefix {
  uint8_t prefix_length;  // Length of prefix in bits (0-8)
  byte_t key;             // The prefix key (relevant bits)
  value_t value;          // Value associated with this prefix

  // Constructor for a new prefix entry
  Prefix(uint8_t len, byte_t k, value_t v)
      : prefix_length(len), key(k), value(v) {}
};

/**
 * Comparison function for sorting prefixes
 * Longer prefixes come first (more specific matches)
 */
bool prefix_compare(const Prefix& p1, const Prefix& p2) {
  // If lengths are equal, compare the actual keys
  if (p1.prefix_length == p2.prefix_length) {
    return p1.key < p2.key;
  }
  
  // Sort by decreasing prefix length (longest prefix first)
  return p1.prefix_length > p2.prefix_length;
}

/**
 * Node in the LPM trie
 */
struct Node {
  std::vector<Branch> branches;  // Child branches from this node
  std::vector<Prefix> prefixes;  // Prefixes stored at this node
  Node* parent{nullptr};         // Parent node for backtracking
  byte_t child_id{0};            // Value in parent's branch pointing to this node

  Node() = default;
  ~Node() = default;

  /**
   * Find the next node for a given byte value
   */
  Node* get_next_node(byte_t byte) const {
    // Binary search for the branch with matching value
    auto it = std::lower_bound(
        branches.begin(), branches.end(), byte,
        [](const Branch& branch, byte_t value) { 
          return branch.value < value; 
        });

    // Return the node if found, otherwise nullptr
    if (it != branches.end() && it->value == byte) {
      return it->next.get();
    }
    return nullptr;
  }

  /**
   * Add or replace a branch to a child node
   */
  void set_next_node(byte_t byte, std::unique_ptr<Node> next_node) {
    // Find where the branch should be (or is)
    auto it = std::lower_bound(
        branches.begin(), branches.end(), byte,
        [](const Branch& branch, byte_t value) { 
          return branch.value < value; 
        });

    if (it != branches.end() && it->value == byte) {
      // Replace existing branch's node
      it->next = std::move(next_node);
    } else {
      // Insert new branch in sorted position
      branches.emplace(it, byte, std::move(next_node));
    }
  }

  /**
   * Remove a branch for a given byte value
   */
  bool delete_branch(byte_t byte) {
    // Find the branch to delete
    auto it = std::lower_bound(
        branches.begin(), branches.end(), byte,
        [](const Branch& branch, byte_t value) { 
          return branch.value < value; 
        });

    if (it != branches.end() && it->value == byte) {
      branches.erase(it);
      return true;  // Branch found and deleted
    }
    return false;   // Branch not found
  }

  /**
   * Add a prefix to this node, or update if it exists
   */
  bool insert_prefix(uint8_t prefix_length, byte_t key, value_t value) {
    Prefix new_prefix{prefix_length, key, value};
    
    // Find where this prefix belongs in sorted order
    auto it = std::lower_bound(
        prefixes.begin(), prefixes.end(), new_prefix,
        [](const Prefix& p1, const Prefix& p2) { 
          return prefix_compare(p1, p2); 
        });

    // Check if this exact prefix already exists
    if (it != prefixes.end() && 
        it->prefix_length == prefix_length && 
        it->key == key) {
      // Update existing prefix's value
      it->value = value;
      return true;  // Prefix was already present
    }

    // Insert new prefix at the right position
    prefixes.emplace(it, prefix_length, key, value);
    return false;  // Prefix was not present before
  }

  /**
   * Find a prefix with the given length and key
   */
  const Prefix* get_prefix(uint8_t prefix_length, byte_t key) const {
    // Create a temporary prefix for comparison
    Prefix search_prefix{prefix_length, key, 0};
    
    // Binary search for the prefix
    auto it = std::lower_bound(
        prefixes.begin(), prefixes.end(), search_prefix,
        [](const Prefix& p1, const Prefix& p2) { 
          return prefix_compare(p1, p2); 
        });

    // Return pointer to prefix if found
    if (it != prefixes.end() && 
        it->prefix_length == prefix_length && 
        it->key == key) {
      return &(*it);
    }
    return nullptr;  // Not found
  }

  /**
   * Get the prefix with length 0 (default route)
   */
  const Prefix* get_empty_prefix() const {
    if (prefixes.empty()) return nullptr;
    
    // Empty prefix would be the least specific (at the end)
    const auto& last_prefix = prefixes.back();
    return (last_prefix.prefix_length == 0) ? &last_prefix : nullptr;
  }

  /**
   * Remove a prefix with the given length and key
   */
  bool delete_prefix(uint8_t prefix_length, byte_t key) {
    // Create a temporary prefix for comparison
    Prefix search_prefix{prefix_length, key, 0};
    
    // Binary search for the prefix
    auto it = std::lower_bound(
        prefixes.begin(), prefixes.end(), search_prefix,
        [](const Prefix& p1, const Prefix& p2) { 
          return prefix_compare(p1, p2); 
        });

    // Delete if found
    if (it != prefixes.end() && 
        it->prefix_length == prefix_length && 
        it->key == key) {
      prefixes.erase(it);
      return true;  // Prefix found and deleted
    }
    return false;   // Prefix not found
  }
};

/**
 * Implementation of BfLpmTrie
 */
class BfLpmTrieImpl {
 public:
  BfLpmTrieImpl(size_t key_width_bytes, bool auto_shrink)
      : root_(std::make_unique<Node>()),
        key_width_bytes_(key_width_bytes),
        release_memory_(auto_shrink) {
    // Sanity check on key width
    assert(key_width_bytes <= 64);
  }

  ~BfLpmTrieImpl() = default;

  /**
   * Insert a prefix into the trie
   */
  void insert(const char* prefix, int prefix_length, value_t value) {
    // For default route with null prefix, use a dummy byte array
    if (prefix == nullptr && prefix_length == 0) {
      static const char dummy_prefix[1] = {0};
      prefix = dummy_prefix;
    } else if (prefix == nullptr) {
      return; // Can't insert non-default route with null prefix
    }

    Node* current = root_.get();
    byte_t byte_val;

    // Navigate/build the trie one byte at a time for complete bytes
    while (prefix_length >= 8) {
      byte_val = static_cast<byte_t>(*prefix);
      
      Node* next = current->get_next_node(byte_val);
      
      if (!next) {
        // Need to create a new node
        auto new_node = std::make_unique<Node>();
        next = new_node.get();
        next->parent = current;
        next->child_id = byte_val;
        current->set_next_node(byte_val, std::move(new_node));
      }

      prefix++;
      prefix_length -= 8;
      current = next;
    }

    // Handle the last partial byte (if any)
    byte_t partial_key = 0;
    if (prefix_length > 0) {
      // Extract the relevant bits from the remaining prefix byte
      partial_key = static_cast<byte_t>(*prefix) & static_cast<byte_t>((0xFF) << (8 - prefix_length));
    }
    
    // Insert the prefix at the current node
    current->insert_prefix(static_cast<uint8_t>(prefix_length), partial_key, value);
  }

  /**
   * Check if a prefix exists in the trie
   */
  bool has_prefix(const char* prefix, int prefix_length) const {
    value_t temp_value;
    return retrieve_value(prefix, prefix_length, &temp_value);
  }

  /**
   * Get the value associated with a prefix
   */
  bool retrieve_value(const char* prefix, int prefix_length, value_t* pvalue) const {
    if (pvalue == nullptr) return false;
    
    // For default route with null prefix, use a dummy byte array
    if (prefix == nullptr && prefix_length == 0) {
      static const char dummy_prefix[1] = {0};
      prefix = dummy_prefix;
    } else if (prefix == nullptr) {
      return false; // Can't retrieve non-default route with null prefix
    }

    const Node* current = root_.get();
    byte_t byte_val;

    // Navigate the trie one byte at a time
    while (prefix_length >= 8) {
      byte_val = static_cast<byte_t>(*prefix);
      const Node* next = current->get_next_node(byte_val);
      
      if (!next) {
        // Path doesn't exist
        return false;
      }

      prefix++;
      prefix_length -= 8;
      current = next;
    }

    // Handle the last partial byte (if any)
    byte_t partial_key = 0;
    if (prefix_length > 0) {
      // Extract the relevant bits from the remaining prefix byte
      partial_key = static_cast<byte_t>(*prefix) & static_cast<byte_t>((0xFF) << (8 - prefix_length));
    }
    
    // Look up the prefix in the current node
    const Prefix* p = current->get_prefix(static_cast<uint8_t>(prefix_length), partial_key);
    if (p == nullptr) {
      return false;
    }

    // Found the prefix, return its value
    *pvalue = p->value;
    return true;
  }

  /**
   * Find the longest matching prefix for a key
   */
  bool lookup(const char* key, value_t* pvalue) const {
    if (key == nullptr || pvalue == nullptr) return false;
    
    const Node* current = root_.get();
    value_t best_value = 0;
    int best_prefix_len = -1;
    bool match_found = false;
    size_t bytes_checked = 0;
    
    // Track the path we follow
    std::vector<const Node*> path;
    path.push_back(current);
    
    // First, traverse the trie based on the key to find the deepest possible node
    while (bytes_checked < key_width_bytes_) {
        byte_t current_key_byte = static_cast<byte_t>(key[bytes_checked]);
        const Node* next = current->get_next_node(current_key_byte);
        if (!next) break;
        
        path.push_back(next);
        current = next;
        bytes_checked++;
    }
    
    // Now check prefixes along the path from deepest to root (most specific to least specific)
    for (auto it = path.rbegin(); it != path.rend(); ++it) {
        const Node* node = *it;
        size_t node_depth = path.rend() - it - 1;  // Distance from root
        
        // Skip empty nodes
        if (node->prefixes.empty()) continue;
        
        // Check the prefixes at this node
        for (const auto& prefix : node->prefixes) {
            // Calculate total prefix length
            int total_prefix_len = (node_depth * 8) + prefix.prefix_length;
            
            // No bits to compare for prefix_length=0 (default route)
            if (prefix.prefix_length == 0) {
                if (total_prefix_len > best_prefix_len) {
                    best_prefix_len = total_prefix_len;
                    best_value = prefix.value;
                    match_found = true;
                }
                continue;
            }
            
            // For non-zero prefix length, check if bits match
            byte_t key_byte = static_cast<byte_t>(key[node_depth]);
            byte_t mask = static_cast<byte_t>((0xFF) << (8 - prefix.prefix_length));
            byte_t masked_key = key_byte & mask;
            byte_t masked_prefix = prefix.key & mask;
            
            if (masked_key == masked_prefix) {
                if (total_prefix_len > best_prefix_len) {
                    best_prefix_len = total_prefix_len;
                    best_value = prefix.value;
                    match_found = true;
                }
            }
        }
        
        // If we found a match at this node, we don't need to check parent nodes
        // because they would be less specific
        if (match_found && best_prefix_len >= 0) {
            break;
        }
    }
    
    // If we found a match, return the value
    if (match_found) {
        *pvalue = best_value;
    }
    
    return match_found;
  }

  /**
   * Delete a prefix from the trie
   */
  bool delete_prefix(const char* prefix, int prefix_length) {
    // For default route with null prefix, use a dummy byte array
    if (prefix == nullptr && prefix_length == 0) {
      static const char dummy_prefix[1] = {0};
      prefix = dummy_prefix;
    } else if (prefix == nullptr) {
      return false; // Can't delete non-default route with null prefix
    }
    
    Node* current = root_.get();
    byte_t byte_val;

    // Navigate the trie one byte at a time
    while (prefix_length >= 8) {
      byte_val = static_cast<byte_t>(*prefix);
      Node* next = current->get_next_node(byte_val);
      
      if (!next) {
        // Path doesn't exist
        return false;
      }

      prefix++;
      prefix_length -= 8;
      current = next;
    }

    // Handle the last partial byte (if any)
    byte_t partial_key = 0;
    if (prefix_length > 0) {
      // Extract the relevant bits from the remaining prefix byte
      partial_key = static_cast<byte_t>(*prefix) & static_cast<byte_t>((0xFF) << (8 - prefix_length));
    }
    
    // Check if the prefix exists
    if (!current->get_prefix(static_cast<uint8_t>(prefix_length), partial_key)) {
      return false;
    }
    
    // Delete the prefix
    bool success = current->delete_prefix(static_cast<uint8_t>(prefix_length), partial_key);
    
    // Clean up empty nodes if requested
    if (success && release_memory_) {
      clean_node(current);
    }
    
    return success;
  }

  /**
   * Clean up empty nodes after deletion
   */
  void clean_node(Node* current) {
    // Clean up empty nodes
    while (current->prefixes.empty() && current->branches.empty()) {
      Node* to_delete = current;
      current = current->parent;
      
      // Stop if we've reached the root
      if (!current) break;
      
      // Remove the branch pointing to the empty node
      bool branch_removed = current->delete_branch(to_delete->child_id);
      assert(branch_removed);
      
      // Child node will be deleted by its unique_ptr when the branch is removed
    }
  }

 private:
  std::unique_ptr<Node> root_;       // Root of the trie
  size_t key_width_bytes_;           // Width of keys in bytes
  bool release_memory_;              // Whether to shrink the trie on deletions
};

// Implementation of BfLpmTrie methods

BfLpmTrie::BfLpmTrie(size_t key_width_bytes, bool auto_shrink)
    : impl_(std::make_unique<BfLpmTrieImpl>(key_width_bytes, auto_shrink)) {}

BfLpmTrie::~BfLpmTrie() = default;

// Move operations
BfLpmTrie::BfLpmTrie(BfLpmTrie&& other) noexcept = default;
BfLpmTrie& BfLpmTrie::operator=(BfLpmTrie&& other) noexcept = default;

// Forward all operations to the implementation
void BfLpmTrie::insert(const char* prefix, int prefix_length, value_t value) {
  if (prefix == nullptr && prefix_length > 0) return; // Guard against null pointers
  impl_->insert(prefix, prefix_length, value);
}

bool BfLpmTrie::has_prefix(const char* prefix, int prefix_length) const {
  if (prefix == nullptr && prefix_length > 0) return false; // Guard against null pointers
  return impl_->has_prefix(prefix, prefix_length);
}

bool BfLpmTrie::retrieve_value(const char* prefix, int prefix_length, value_t* pvalue) const {
  if (prefix == nullptr && prefix_length > 0) return false; // Guard against null pointers
  if (pvalue == nullptr) return false; // Guard against null value pointer
  return impl_->retrieve_value(prefix, prefix_length, pvalue);
}

bool BfLpmTrie::lookup(const char* key, value_t* pvalue) const {
  if (key == nullptr || pvalue == nullptr) return false; // Guard against null pointers
  return impl_->lookup(key, pvalue);
}

bool BfLpmTrie::delete_prefix(const char* prefix, int prefix_length) {
  if (prefix == nullptr && prefix_length > 0) return false; // Guard against null pointers
  return impl_->delete_prefix(prefix, prefix_length);
}

//----------------------------------------------------------------------
// C API implementation for backward compatibility
//----------------------------------------------------------------------
extern "C" {

// Wrapper struct that holds a C++ implementation
struct bf_lpm_trie_s {
  std::unique_ptr<BfLpmTrie> trie;
};

bf_lpm_trie_t* bf_lpm_trie_create(size_t key_width_bytes, bool auto_shrink) {
  // Allocate a new wrapper
  bf_lpm_trie_t* trie = new bf_lpm_trie_t;
  // Create the actual C++ implementation
  trie->trie = std::make_unique<BfLpmTrie>(key_width_bytes, auto_shrink);
  return trie;
}

void bf_lpm_trie_destroy(bf_lpm_trie_t* t) {
  // Clean up the wrapper and the C++ object it contains
  delete t;
}

// Forward C API calls to C++ implementation
void bf_lpm_trie_insert(bf_lpm_trie_t* trie, const char* prefix, int prefix_length, const value_t value) {
  trie->trie->insert(prefix, prefix_length, value);
}

bool bf_lpm_trie_has_prefix(const bf_lpm_trie_t* trie, const char* prefix, int prefix_length) {
  return trie->trie->has_prefix(prefix, prefix_length);
}

bool bf_lpm_trie_retrieve_value(const bf_lpm_trie_t* trie, const char* prefix, int prefix_length, value_t* pvalue) {
  return trie->trie->retrieve_value(prefix, prefix_length, pvalue);
}

bool bf_lpm_trie_lookup(const bf_lpm_trie_t* trie, const char* key, value_t* pvalue) {
  return trie->trie->lookup(key, pvalue);
}

bool bf_lpm_trie_delete(bf_lpm_trie_t* trie, const char* prefix, int prefix_length) {
  return trie->trie->delete_prefix(prefix, prefix_length);
}

}  // extern "C"

}  // namespace bm 