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
 * Gordon Bailey (gb@gordonbailey.net)
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/_assert.h>
#include <bm/bm_sim/lookup_structures.h>
#include <bm/bm_sim/match_key_types.h>

#include <algorithm>  // for std::swap
#include <unordered_map>
#include <vector>
#include <tuple>
#include <limits>
#include <list>
#include <mutex>

#include "lpm_trie.h"

namespace bm {

namespace {  // anonymous

static_assert(sizeof(uintptr_t) == sizeof(internal_handle_t),
              "Invalid type sizes");

// We don't need or want to export these classes outside of this
// compilation unit.

class LPMTrieStructure : public LPMLookupStructure {
 public:
  explicit LPMTrieStructure(size_t key_width_bytes)
    : trie(key_width_bytes) {
    }

  /* Copy constructor */
  LPMTrieStructure(const LPMTrieStructure &other) = delete;

  /* Move constructor */
  LPMTrieStructure(LPMTrieStructure &&other) noexcept = default;

  ~LPMTrieStructure() = default;

  /* Copy assignment operator */
  LPMTrieStructure &operator=(const LPMTrieStructure &other) = delete;

  /* Move assignment operator */
  LPMTrieStructure &operator=(LPMTrieStructure &&other) noexcept = default;

  bool lookup(const ByteContainer &key_data,
              internal_handle_t *handle) const override {
    return trie.lookup(key_data, reinterpret_cast<uintptr_t *>(handle));
  }

  bool entry_exists(const LPMMatchKey &key) const override {
    return trie.has_prefix(key.data, key.prefix_length);
  }

  bool retrieve_handle(const LPMMatchKey &key,
                       internal_handle_t *handle) const override {
    return trie.retrieve_value(key.data, key.prefix_length,
                               reinterpret_cast<uintptr_t *>(handle));
  }

  void add_entry(const LPMMatchKey &key,
                 internal_handle_t handle) override {
    trie.insert_prefix(key.data, key.prefix_length,
                       reinterpret_cast<uintptr_t>(handle));
  }

  void delete_entry(const LPMMatchKey &key) override {
    trie.delete_prefix(key.data, key.prefix_length);
  }

  void clear() override {
    trie.clear();
  }

 private:
  LPMTrie trie;
};

class ExactMap : public ExactLookupStructure {
 public:
  explicit ExactMap(size_t size) {
    entries_map.reserve(size);
  }

  bool lookup(const ByteContainer &key,
              internal_handle_t *handle) const override {
    const auto entry_it = entries_map.find(key);
    if (entry_it == entries_map.end()) {
      return false;  // Nothing found
    } else {
      *handle = entry_it->second;
      return true;
    }
  }

  bool entry_exists(const ExactMatchKey &key) const override {
    return entries_map.find(key.data) != entries_map.end();
  }

  bool retrieve_handle(const ExactMatchKey &key,
                       internal_handle_t *handle) const override {
    const auto it = entries_map.find(key.data);
    if (it == entries_map.cend()) return false;
    *handle = it->second;
    return true;
  }

  void add_entry(const ExactMatchKey &key,
                 internal_handle_t handle) override {
    entries_map[key.data] = handle;  // key is copied, which is not great
  }

  void delete_entry(const ExactMatchKey &key) override {
    entries_map.erase(key.data);
  }

  void clear() override {
    entries_map.clear();
  }

 private:
  std::unordered_map<ByteContainer, internal_handle_t, ByteContainerKeyHash>
    entries_map{};
};

template <size_t S = 64>
class TernaryCache {
 public:
  TernaryCache() {
    cache.reserve(S);
  }

  TernaryCache(const TernaryCache& other) = delete;
  TernaryCache &operator =(const TernaryCache& other) = delete;

  TernaryCache(TernaryCache&& other)= delete;
  TernaryCache &operator =(TernaryCache &&other) = delete;

  bool lookup(const ByteContainer &key_data, internal_handle_t *handle) {
    std::unique_lock<std::mutex> lock(mutex);
    auto it = cache.find(key_data);
    if (it != cache.end()) {
      *handle = it->second->handle;
      move_to_head(it);
      return true;
    }
    return false;
  }

  bool add(const ByteContainer &key_data, internal_handle_t handle) {
    std::unique_lock<std::mutex> lock(mutex);
    auto it = cache.find(key_data);
    if (it != cache.end()) return false;
    if (cache.size() == S) {  // cache is full
      auto evict = entries.back();
      int success = cache.erase(evict.key);
      _BM_UNUSED(success);
      assert(success == 1);
      entries.pop_back();
    }
    entries.emplace_front(handle, key_data);
    cache.emplace(key_data, entries.begin());
    return true;
  }

  // we are being very conservative and invalidating the whole cache every time
  // the table is modified
  void invalidate_all() {
    // this lock may not be strictly needed here, since this method is only
    // called for table operations involving the write lock
    std::unique_lock<std::mutex> lock(mutex);
    cache.clear();
    entries.clear();
  }

 private:
  struct CacheEntry {
    CacheEntry(internal_handle_t handle, const ByteContainer &key)
        : handle(handle), key(key) { }

    internal_handle_t handle;
    ByteContainer key;
  };

  std::list<CacheEntry> entries{};

// I believe that g++-4.8 does not implement std::list correctly (according to
// the C++11 standard): erase does not accept a const_iterator and splice is not
// implemented properly (see below).
#if defined(__clang__) || __GNUC__ >= 5 || (__GNUC__ == 4 && __GNUC_MINOR__ > 8)
  using entries_iterator = typename decltype(entries)::const_iterator;
#else
  using entries_iterator = typename decltype(entries)::iterator;
#endif

  // should we avoid the 2 copies of the key by using a pointer in the map and
  // defining custom hash and eq
  std::unordered_map<ByteContainer, entries_iterator, ByteContainerKeyHash>
  cache{};
  mutable std::mutex mutex{};

  // this is more complicated that it needs to be because of buggy g++-4.8
  void move_to_head(typename decltype(cache)::iterator map_it) {
#if defined(__clang__) || __GNUC__ >= 5 || (__GNUC__ == 4 && __GNUC_MINOR__ > 8)
    // move to head, without any copies
    entries.splice(entries.begin(), entries, map_it->second);
#else
    // Apparently g++-4.8 does not implement std::list::splice properly, but
    // implements it in the C++03 way, which does not require splice to keep all
    // iterators valid (unlike C++11).
    auto it = map_it->second;
    entries.push_front(*it);
    entries.erase(it);
    // need to update the iterator in the cache unlike with splice where the
    // iterator is preserved
    map_it->second = entries.begin();
#endif
  }
};

bool operator==(const TernaryMatchKey &k1, const TernaryMatchKey &k2) {
  return (k1.data == k2.data && k1.mask == k2.mask);
}

bool operator==(const RangeMatchKey &k1, const RangeMatchKey &k2) {
  return (k1.data == k2.data && k1.mask == k2.mask &&
          k1.range_widths == k2.range_widths);
}

// used by both TernaryMap and RangeMap
template <typename K>
class EntryList {
 public:
  EntryList(size_t size, bool enable_cache)
      : entries(size), enable_cache(enable_cache) { }

  template <typename Compare>
  bool lookup(const ByteContainer &key_data, internal_handle_t *handle,
              Compare cmp) const {
    if (cache_activated()) {
      auto in_cache = cache.lookup(key_data, handle);
      if (in_cache) return true;
    }

    auto min_priority =
        std::numeric_limits<decltype(TernaryMatchKey::priority)>::max();

    const Entry *min_entry = nullptr;
    internal_handle_t min_handle = 0;

    for (const Entry *entry = head; entry; entry = entry->next) {
      if (entry->priority >= min_priority) continue;

      if (cmp(key_data, *entry->key)) {
        min_priority = entry->priority;
        min_entry = entry;
        min_handle = handle_from_entry(entry);
      }
    }

    if (min_entry) {
      *handle = min_handle;
      if (cache_activated()) cache.add(key_data, min_handle);
      return true;
    }

    return false;
  }

  bool exists(const K &key) const {
    auto entry = find_entry(key);
    return (entry != nullptr);
  }

  bool retrieve_handle(const K &key, internal_handle_t *handle) const {
    auto entry = find_entry(key);
    if (entry == nullptr) return false;
    *handle = handle_from_entry(entry);
    return true;
  }

  void add(const K &key, internal_handle_t handle) {
    Entry &entry = entries.at(handle);
    entry.priority = key.priority;
    entry.key = &key;

    if (handle == 0) {
      entry.prev = nullptr;
      entry.next = head;
      head = &entry;
      if (entry.next) entry.next->prev = &entry;
    } else {
      assert(&entry != head);
      // this uses knowledge about how the match unit allocates handles;
      // basically if a handle is allocated, in means all handles before it have
      // already been allocated.
      Entry &prev_entry = entries[handle - 1];
      entry.prev = &prev_entry;
      entry.next = prev_entry.next;
      prev_entry.next = &entry;
      if (entry.next) entry.next->prev = &entry;
    }
    entries_count++;
    if (cache_activated()) cache.invalidate_all();
    update_use_cache();
  }

  void delete_entry(const K &key) {
    auto entry = find_entry(key);
    assert(entry);
    if (entry->prev)
      entry->prev->next = entry->next;
    else
      head = entry->next;
    if (entry->next) entry->next->prev = entry->prev;
    entries_count--;
    if (cache_activated()) cache.invalidate_all();
    update_use_cache();
  }

  void clear() {
    head = nullptr;
    cache.invalidate_all();
    entries_count = 0;
    update_use_cache();
  }

 private:
  struct Entry {
    int priority;  // duplicated on purpose (for efficiency although debatable)
    const K *key;
    Entry *prev;
    Entry *next;
  };

  Entry *head{nullptr};
  std::vector<Entry> entries;
  size_t entries_count{0};

  bool enable_cache;
  bool use_cache{false};
  mutable TernaryCache<> cache{};

  static constexpr size_t cache_activation_min_entries = 16;

  internal_handle_t handle_from_entry(const Entry *entry) const {
    return std::distance(&entries[0], entry);
  }

  const Entry *find_entry(const K &key) const {
    for (Entry *entry = head; entry; entry = entry->next) {
      if (entry->priority == key.priority && *entry->key == key)
        return entry;
    }
    return nullptr;
  }

  bool cache_activated() const {
    return use_cache;
  }

  void update_use_cache() {
    use_cache = enable_cache && (entries_count >= cache_activation_min_entries);
  }
};

class TernaryMap : public TernaryLookupStructure {
 public:
  TernaryMap(size_t size, size_t nbytes_key, bool enable_cache = true)
      : entry_list(size, enable_cache), nbytes_key(nbytes_key) {}

  bool lookup(const ByteContainer &key_data,
              internal_handle_t *handle) const override {
    auto cmp = [this](const ByteContainer &key_data, const TernaryMatchKey &k) {
      for (size_t byte_index = 0; byte_index < this->nbytes_key; byte_index++) {
        if (k.data[byte_index] != (key_data[byte_index] & k.mask[byte_index]))
          return false;
      }
      return true;
    };

    return entry_list.lookup(key_data, handle, cmp);
  }

  bool entry_exists(const TernaryMatchKey &key) const override {
    return entry_list.exists(key);
  }

  bool retrieve_handle(const TernaryMatchKey &key,
                       internal_handle_t *handle) const override {
    return entry_list.retrieve_handle(key, handle);
  }

  void add_entry(const TernaryMatchKey &key,
                 internal_handle_t handle) override {
    entry_list.add(key, handle);
  }

  void delete_entry(const TernaryMatchKey &key) override {
    entry_list.delete_entry(key);
  }

  void clear() override {
    entry_list.clear();
  }

 private:
  EntryList<TernaryMatchKey> entry_list;
  size_t nbytes_key;
};

class RangeMap : public RangeLookupStructure {
 public:
  RangeMap(size_t size, size_t nbytes_key, bool enable_cache = true)
      : entry_list(size, enable_cache), nbytes_key(nbytes_key) {}

  bool lookup(const ByteContainer &key_data,
              internal_handle_t *handle) const override {
    auto cmp = [this](const ByteContainer &key_data, const RangeMatchKey &k) {
      size_t offset = 0;
      for (const int w : k.range_widths) {
        if (memcmp(&key_data[offset], &k.data[offset], w) < 0) {
          return false;
        }
        if (memcmp(&key_data[offset], &k.mask[offset], w) > 0) {
          return false;
        }
        offset += w;
      }

      for (; offset < nbytes_key; offset++) {
        if (k.data[offset] != (key_data[offset] & k.mask[offset]))
          return false;
      }

      return true;
    };

    return entry_list.lookup(key_data, handle, cmp);
  }

  bool entry_exists(const RangeMatchKey &key) const override {
    return entry_list.exists(key);
  }

  bool retrieve_handle(const RangeMatchKey &key,
                       internal_handle_t *handle) const override {
    return entry_list.retrieve_handle(key, handle);
  }

  void add_entry(const RangeMatchKey &key,
                 internal_handle_t handle) override {
    entry_list.add(key, handle);
  }

  void delete_entry(const RangeMatchKey &key) override {
    entry_list.delete_entry(key);
  }

  void clear() override {
    entry_list.clear();
  }

 private:
  EntryList<RangeMatchKey> entry_list;
  size_t nbytes_key;
};

}  // namespace

LookupStructureFactory::LookupStructureFactory(bool enable_ternary_cache)
    : enable_ternary_cache(enable_ternary_cache) { }

template <>
std::unique_ptr<LookupStructure<ExactMatchKey> >
LookupStructureFactory::create<ExactMatchKey>(
    LookupStructureFactory *f, size_t size, size_t nbytes_key) {
  return f->create_for_exact(size, nbytes_key);
}

template <>
std::unique_ptr<LookupStructure<LPMMatchKey> >
LookupStructureFactory::create<LPMMatchKey>(
    LookupStructureFactory *f, size_t size, size_t nbytes_key) {
  return f->create_for_LPM(size, nbytes_key);
}

template <>
std::unique_ptr<LookupStructure<TernaryMatchKey> >
LookupStructureFactory::create<TernaryMatchKey>(
    LookupStructureFactory *f, size_t size, size_t nbytes_key) {
  return f->create_for_ternary(size, nbytes_key);
}

template <>
std::unique_ptr<LookupStructure<RangeMatchKey> >
LookupStructureFactory::create<RangeMatchKey>(
    LookupStructureFactory *f, size_t size, size_t nbytes_key) {
  return f->create_for_range(size, nbytes_key);
}


std::unique_ptr<ExactLookupStructure>
LookupStructureFactory::create_for_exact(size_t size, size_t nbytes_key) {
  (void) nbytes_key;
  return std::unique_ptr<ExactLookupStructure>(new ExactMap(size));
}

std::unique_ptr<LPMLookupStructure>
LookupStructureFactory::create_for_LPM(size_t size, size_t nbytes_key) {
  (void) size;
  return std::unique_ptr<LPMLookupStructure>(new LPMTrieStructure(nbytes_key));
}

std::unique_ptr<TernaryLookupStructure>
LookupStructureFactory::create_for_ternary(size_t size, size_t nbytes_key) {
  return std::unique_ptr<TernaryLookupStructure>(
      new TernaryMap(size, nbytes_key, enable_ternary_cache));
}

std::unique_ptr<RangeLookupStructure>
LookupStructureFactory::create_for_range(size_t size, size_t nbytes_key) {
  return std::unique_ptr<RangeLookupStructure>(
      new RangeMap(size, nbytes_key, enable_ternary_cache));
}

}  // namespace bm
