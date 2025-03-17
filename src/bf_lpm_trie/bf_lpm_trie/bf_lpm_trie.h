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

#ifndef BF_LPM_TRIE_H_
#define BF_LPM_TRIE_H_

#include <cstddef>
#include <cstdint>
#include <memory>

namespace bm {

// Define value_t as an alias for uintptr_t for consistency with the C API
using value_t = uintptr_t;

// Forward declaration - implementation details hidden from users
class BfLpmTrieImpl;

/**
 * @brief A modern C++ implementation of Longest Prefix Match trie
 * 
 * This class implements a LPM trie data structure optimized for IP lookup.
 * It supports variable-length prefixes and provides fast lookup operations.
 * The implementation uses the PIMPL idiom for better encapsulation.
 */
class BfLpmTrie {
 public:
  /**
   * Constructor for the LPM trie
   * 
   * @param key_width_bytes Width of keys in bytes (max 64)
   * @param auto_shrink Whether the trie should automatically shrink when entries are removed
   */
  BfLpmTrie(size_t key_width_bytes, bool auto_shrink);
  
  /**
   * Destructor
   */
  ~BfLpmTrie();

  // No copy semantics - tries can be large, so copying is expensive
  BfLpmTrie(const BfLpmTrie&) = delete;
  BfLpmTrie& operator=(const BfLpmTrie&) = delete;

  // Support move semantics for efficient ownership transfer
  BfLpmTrie(BfLpmTrie&&) noexcept;
  BfLpmTrie& operator=(BfLpmTrie&&) noexcept;

  /**
   * Insert a prefix into the trie
   * 
   * @param prefix Byte array representing the prefix to insert
   * @param prefix_length Length of the prefix in bits
   * @param value Value to associate with the prefix
   */
  void insert(const char* prefix, int prefix_length, value_t value);

  /**
   * Check if a prefix exists in the trie
   * 
   * @param prefix Byte array representing the prefix to check
   * @param prefix_length Length of the prefix in bits
   * @return true if the prefix exists, false otherwise
   */
  bool has_prefix(const char* prefix, int prefix_length) const;

  /**
   * Retrieve the value associated with a prefix
   * 
   * @param prefix Byte array representing the prefix to look up
   * @param prefix_length Length of the prefix in bits
   * @param pvalue Pointer to store the retrieved value
   * @return true if the prefix was found, false otherwise
   */
  bool retrieve_value(const char* prefix, int prefix_length, value_t* pvalue) const;

  /**
   * Lookup a key in the trie, matching the longest prefix
   * 
   * @param key Byte array representing the key to look up
   * @param pvalue Pointer to store the matched value
   * @return true if a match was found, false otherwise
   */
  bool lookup(const char* key, value_t* pvalue) const;

  /**
   * Delete a prefix from the trie
   * 
   * @param prefix Byte array representing the prefix to delete
   * @param prefix_length Length of the prefix in bits
   * @return true if the prefix was deleted, false if it didn't exist
   */
  bool delete_prefix(const char* prefix, int prefix_length);

 private:
  // Implementation details hidden via PIMPL idiom
  std::unique_ptr<BfLpmTrieImpl> impl_;
};

// C compatibility layer for backward compatibility
extern "C" {

// Opaque type for C API
struct bf_lpm_trie_s;
typedef struct bf_lpm_trie_s bf_lpm_trie_t;

// C API functions with same semantics as the C++ methods
bf_lpm_trie_t* bf_lpm_trie_create(size_t key_width_bytes, bool auto_shrink);
void bf_lpm_trie_destroy(bf_lpm_trie_t* t);
void bf_lpm_trie_insert(bf_lpm_trie_t* trie, const char* prefix, int prefix_length, const value_t value);
bool bf_lpm_trie_has_prefix(const bf_lpm_trie_t* trie, const char* prefix, int prefix_length);
bool bf_lpm_trie_retrieve_value(const bf_lpm_trie_t* trie, const char* prefix, int prefix_length, value_t* pvalue);
bool bf_lpm_trie_lookup(const bf_lpm_trie_t* trie, const char* key, value_t* pvalue);
bool bf_lpm_trie_delete(bf_lpm_trie_t* trie, const char* prefix, int prefix_length);

}  // extern "C"

}  // namespace bm

#endif  // BF_LPM_TRIE_H_ 