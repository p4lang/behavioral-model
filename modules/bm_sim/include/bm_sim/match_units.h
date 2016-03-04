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

#ifndef BM_SIM_INCLUDE_BM_SIM_MATCH_UNITS_H_
#define BM_SIM_INCLUDE_BM_SIM_MATCH_UNITS_H_

// shared_mutex will only be available in C++-14, so for now I'm using boost
#include <boost/thread/shared_mutex.hpp>

#include <string>
#include <unordered_map>
#include <vector>
#include <iostream>
#include <atomic>
#include <utility>  // for pair<>

#include "match_error_codes.h"
#include "bytecontainer.h"
#include "phv.h"
#include "packet.h"
#include "handle_mgr.h"
#include "lpm_trie.h"
#include "counters.h"
#include "meters.h"

namespace bm {

typedef uintptr_t internal_handle_t;
typedef uint64_t entry_handle_t;

// using string and not ByteContainer for efficiency
struct MatchKeyParam {
  // order is important, implementation sorts match fields according to their
  // match type based on this order
  enum class Type {
    VALID,
    EXACT,
    LPM,
    TERNARY
  };

  MatchKeyParam(const Type &type, std::string key)
    : type(type), key(std::move(key)) { }

  MatchKeyParam(const Type &type, std::string key, std::string mask)
    : type(type), key(std::move(key)), mask(std::move(mask)) { }

  MatchKeyParam(const Type &type, std::string key, int prefix_length)
    : type(type), key(std::move(key)), prefix_length(prefix_length) { }

  friend std::ostream& operator<<(std::ostream &out, const MatchKeyParam &p);

  static std::string type_to_string(Type t);

  Type type;
  std::string key;
  std::string mask{};  // optional
  int prefix_length{0};  // optional
};

enum class MatchUnitType {
  EXACT, LPM, TERNARY
};


namespace detail {

class MatchKeyBuilderHelper;

}  // namespace detail

// Fields should be pushed in the P4 program (i.e. JSON) order. Internally, they
// will be re-ordered for a more efficient implementation.
class MatchKeyBuilder {
  friend class detail::MatchKeyBuilderHelper;
 public:
  void push_back_field(header_id_t header, int field_offset, size_t nbits,
                       MatchKeyParam::Type mtype, const std::string &name = "");

  void push_back_field(header_id_t header, int field_offset, size_t nbits,
                       const ByteContainer &mask, MatchKeyParam::Type mtype,
                       const std::string &name = "");

  void push_back_valid_header(header_id_t header, const std::string &name = "");

  void apply_big_mask(ByteContainer *key) const;

  void operator()(const PHV &phv, ByteContainer *key) const;

  std::vector<std::string> key_to_fields(const ByteContainer &key) const;

  std::string key_to_string(const ByteContainer &key,
                            std::string separator = "",
                            bool upper_case = false) const;

  void build();

  template <typename E>
  std::vector<MatchKeyParam> entry_to_match_params(const E &entry) const;

  template <typename E>
  E match_params_to_entry(const std::vector<MatchKeyParam> &params) const;

  bool match_params_sanity_check(
      const std::vector<MatchKeyParam> &params) const;

  size_t get_nbytes_key() const { return nbytes_key; }

  const std::string &get_name(size_t idx) const { return name_map.get(idx); }

  size_t max_name_size() const { return name_map.max_size(); }

 private:
  struct KeyF {
    header_id_t header;
    int f_offset;
    MatchKeyParam::Type mtype;
    size_t nbits;
  };

  struct NameMap {
    void push_back(const std::string &name);
    const std::string &get(size_t idx) const;
    size_t max_size() const;

    std::vector<std::string> names{};
    size_t max_s{0};
  };

  // takes ownership of input
  void push_back(KeyF &&input, const ByteContainer &mask,
                 const std::string &name);

  std::vector<KeyF> key_input{};
  size_t nbytes_key{0};
  bool has_big_mask{false};
  ByteContainer big_mask{};
  // maps the position of the field in the original P4 key to its actual
  // position in the implementation-specific key. In the implementation, VALID
  // match keys come first, followed by EXACT, then LPM and TERNARY.
  std::vector<size_t> key_mapping{};
  // inverse of key_mapping, could be handy
  std::vector<size_t> inv_mapping{};
  std::vector<size_t> key_offsets{};
  NameMap name_map{};
  bool built{false};
  std::vector<ByteContainer> masks{};
};

namespace MatchUnit {

struct AtomicTimestamp {
  std::atomic<uint64_t> ms_{};

  AtomicTimestamp() { }

  template <typename T>
  explicit AtomicTimestamp(const T &tp) {
    ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(
      tp.time_since_epoch()).count();
  }

  explicit AtomicTimestamp(uint64_t ms)
    : ms_(ms) { }

  template <typename T>
  void set(const T &tp) {
    ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(
      tp.time_since_epoch()).count();
  }

  void set(uint64_t ms) {
    ms_ = ms;
  }

  uint64_t get_ms() const {
    return ms_;
  }

  /* don't need these (for now?), so remove them */
  AtomicTimestamp(const AtomicTimestamp &other) = delete;
  AtomicTimestamp &operator=(const AtomicTimestamp &other) = delete;

  /* std::atomic<T> is non-movable so I have to define this myself */
  AtomicTimestamp(AtomicTimestamp &&other)
    : ms_(other.ms_.load()) { }
  AtomicTimestamp &operator=(AtomicTimestamp &&other) {
    ms_ = other.ms_.load();
    return *this;
  }
};

struct EntryMeta {
  typedef Packet::clock clock;

  AtomicTimestamp ts{};
  uint32_t timeout_ms{0};
  Counter counter{};
  uint32_t version{};

  void reset() {
    counter.reset_counter();
    ts.set(clock::now());
  }
};

}  // namespace MatchUnit

class MatchUnitAbstract_ {
 public:
  MatchUnitAbstract_(size_t size, const MatchKeyBuilder &key_builder)
    : size(size), nbytes_key(key_builder.get_nbytes_key()),
      match_key_builder(key_builder), entry_meta(size) {
    match_key_builder.build();
  }

  size_t get_num_entries() const { return num_entries; }

  size_t get_size() const { return size; }

  size_t get_nbytes_key() const { return nbytes_key; }

  bool valid_handle(entry_handle_t handle) const;

  MatchUnit::EntryMeta &get_entry_meta(entry_handle_t handle);
  const MatchUnit::EntryMeta &get_entry_meta(entry_handle_t handle) const;

  void reset_counters();

  void set_direct_meters(MeterArray *meter_array);

  Meter &get_meter(entry_handle_t handle);

  MatchErrorCode set_entry_ttl(entry_handle_t handle, unsigned int ttl_ms);

  void sweep_entries(std::vector<entry_handle_t> *entries) const;

  void dump_key_params(std::ostream *out,
                       const std::vector<MatchKeyParam> &params,
                       int priority = -1) const;

 protected:
  MatchErrorCode get_and_set_handle(internal_handle_t *handle);
  MatchErrorCode unset_handle(internal_handle_t handle);
  bool valid_handle_(internal_handle_t handle) const;

  void build_key(const PHV &phv, ByteContainer *key) const {
    match_key_builder(phv, key);
  }

  std::string key_to_string(const ByteContainer &key) const {
    return match_key_builder.key_to_string(key);
  }

  std::string key_to_string_with_names(const ByteContainer &key) const;

  void update_counters(Counter *c, const Packet &pkt) {
    c->increment_counter(pkt);
  }

  void update_ts(MatchUnit::AtomicTimestamp *ts, const Packet &pkt) {
    ts->set(pkt.get_ingress_ts_ms());
  }

 protected:
  ~MatchUnitAbstract_() { }

 protected:
  size_t size{0};
  size_t num_entries{0};
  size_t nbytes_key;
  HandleMgr handles{};
  MatchKeyBuilder match_key_builder;
  std::vector<MatchUnit::EntryMeta> entry_meta{};
  // non-owning pointer, the meter array still belongs to P4Objects
  MeterArray *direct_meters{nullptr};
};

template <typename V>
class MatchUnitAbstract : public MatchUnitAbstract_ {
 public:
  struct MatchUnitLookup {
    MatchUnitLookup(entry_handle_t handle, const V *value)
      : handle(handle), value(value) { }

    bool found() const { return (value != nullptr); }

    static MatchUnitLookup empty_entry() { return MatchUnitLookup(0, nullptr); }

    entry_handle_t handle{0};
    const V *value{nullptr};
  };

 public:
  MatchUnitAbstract(size_t size, const MatchKeyBuilder &match_key_builder)
    : MatchUnitAbstract_(size, match_key_builder) { }

  virtual ~MatchUnitAbstract() { }

  MatchUnitLookup lookup(const Packet &pkt);

  MatchErrorCode add_entry(const std::vector<MatchKeyParam> &match_key,
                           V value,  // by value for possible std::move
                           entry_handle_t *handle,
                           int priority = -1);

  MatchErrorCode delete_entry(entry_handle_t handle);

  MatchErrorCode modify_entry(entry_handle_t handle, V value);

  MatchErrorCode get_value(entry_handle_t handle, const V **value);

  MatchErrorCode get_entry(entry_handle_t handle,
                           std::vector<MatchKeyParam> *match_key,
                           const V **value, int *priority = nullptr) const;

  // TODO(antonin): move this one level up in class hierarchy?
  // will return an empty string if the handle is not valid
  // otherwise will return a dump of the match entry in a nice format
  // Dumping entry <handle>
  // Match key:
  //   param_1
  //   param_2 ...
  // [Priority: ...]
  // Does not print anything related to the stored value
  std::string entry_to_string(entry_handle_t handle) const;

  MatchErrorCode dump_match_entry(std::ostream *out,
                                  entry_handle_t handle) const;

  void dump(std::ostream *stream) const {
    return dump_(stream);
  }

  void reset_state();

 private:
  virtual MatchErrorCode add_entry_(const std::vector<MatchKeyParam> &match_key,
                                    V value,  // by value for possible std::move
                                    entry_handle_t *handle,
                                    int priority) = 0;

  virtual MatchErrorCode delete_entry_(entry_handle_t handle) = 0;

  virtual MatchErrorCode modify_entry_(entry_handle_t handle, V value) = 0;

  virtual MatchErrorCode get_value_(entry_handle_t handle, const V **value) = 0;

  virtual MatchErrorCode get_entry_(entry_handle_t handle,
                                    std::vector<MatchKeyParam> *match_key,
                                    const V **value, int *priority) const = 0;

  virtual MatchErrorCode dump_match_entry_(std::ostream *out,
                                           entry_handle_t handle) const = 0;

  virtual void dump_(std::ostream *stream) const = 0;

  virtual void reset_state_() = 0;

  virtual MatchUnitLookup lookup_key(const ByteContainer &key) const = 0;
};

// TODO(antonin):
// It seems that with the recent additions, these classes would really benefit
// from inheriting from a common ancestor templatized by the entry type

template <typename V>
class MatchUnitExact : public MatchUnitAbstract<V> {
 public:
  typedef typename MatchUnitAbstract<V>::MatchUnitLookup MatchUnitLookup;

 public:
  MatchUnitExact(size_t size, const MatchKeyBuilder &match_key_builder)
    : MatchUnitAbstract<V>(size, match_key_builder),
      entries(size) {
    entries_map.reserve(size);
  }

 private:
  // TODO(antonin): have all Entry structs inherit from a common base?
  struct Entry {
    Entry() { }

    Entry(ByteContainer key, V value, uint32_t version)
      : key(std::move(key)), value(std::move(value)), version(version) { }

    ByteContainer key{};
    V value{};
    uint32_t version{0};

    static constexpr MatchUnitType mut = MatchUnitType::EXACT;
  };

 private:
  MatchErrorCode add_entry_(const std::vector<MatchKeyParam> &match_key,
                            V value,  // by value for possible std::move
                            entry_handle_t *handle,
                            int priority) override;

  MatchErrorCode delete_entry_(entry_handle_t handle) override;

  MatchErrorCode modify_entry_(entry_handle_t handle, V value) override;

  MatchErrorCode get_value_(entry_handle_t handle, const V **value) override;

  MatchErrorCode get_entry_(entry_handle_t handle,
                            std::vector<MatchKeyParam> *match_key,
                            const V **value, int *priority) const override;

  MatchErrorCode dump_match_entry_(std::ostream *out,
                                   entry_handle_t handle) const override;

  void dump_(std::ostream *stream) const override;

  void reset_state_() override;

  MatchUnitLookup lookup_key(const ByteContainer &key) const override;

 private:
  std::vector<Entry> entries{};
  std::unordered_map<ByteContainer, entry_handle_t, ByteContainerKeyHash>
  entries_map{};
};

template <typename V>
class MatchUnitLPM : public MatchUnitAbstract<V> {
 public:
  typedef typename MatchUnitAbstract<V>::MatchUnitLookup MatchUnitLookup;

 public:
  MatchUnitLPM(size_t size, const MatchKeyBuilder &match_key_builder)
    : MatchUnitAbstract<V>(size, match_key_builder),
      entries(size),
      entries_trie(this->nbytes_key) { }

 private:
  struct Entry {
    Entry() { }

    Entry(ByteContainer key, int prefix_length, V value, uint32_t version)
      : key(std::move(key)), prefix_length(prefix_length),
        value(std::move(value)), version(version) { }

    ByteContainer key{};
    int prefix_length{0};
    V value{};
    uint32_t version{0};

    static constexpr MatchUnitType mut = MatchUnitType::LPM;
  };

 private:
  MatchErrorCode add_entry_(const std::vector<MatchKeyParam> &match_key,
                            V value,  // by value for possible std::move
                            entry_handle_t *handle,
                            int priority) override;

  MatchErrorCode delete_entry_(entry_handle_t handle) override;

  MatchErrorCode modify_entry_(entry_handle_t handle, V value) override;

  MatchErrorCode get_value_(entry_handle_t handle, const V **value) override;

  MatchErrorCode get_entry_(entry_handle_t handle,
                            std::vector<MatchKeyParam> *match_key,
                            const V **value, int *priority) const override;

  MatchErrorCode dump_match_entry_(std::ostream *out,
                                   entry_handle_t handle) const override;

  void dump_(std::ostream *stream) const override;

  void reset_state_() override;

  MatchUnitLookup lookup_key(const ByteContainer &key) const override;

 private:
  std::vector<Entry> entries{};
  LPMTrie entries_trie;
};

template <typename V>
class MatchUnitTernary : public MatchUnitAbstract<V> {
 public:
  typedef typename MatchUnitAbstract<V>::MatchUnitLookup MatchUnitLookup;

 public:
  MatchUnitTernary(size_t size, const MatchKeyBuilder &match_key_builder)
    : MatchUnitAbstract<V>(size, match_key_builder),
      entries(size) { }

 private:
  struct Entry {
    Entry() { }

    Entry(ByteContainer key, ByteContainer mask, int priority, V value,
          uint32_t version)
      : key(std::move(key)), mask(std::move(mask)), priority(priority),
        value(std::move(value)), version(version) { }

    ByteContainer key{};
    ByteContainer mask{};
    int priority{0};
    V value{};
    uint32_t version{0};

    static constexpr MatchUnitType mut = MatchUnitType::TERNARY;
  };

 private:
  MatchErrorCode add_entry_(const std::vector<MatchKeyParam> &match_key,
                            V value,  // by value for possible std::move
                            entry_handle_t *handle,
                            int priority) override;

  MatchErrorCode delete_entry_(entry_handle_t handle) override;

  MatchErrorCode modify_entry_(entry_handle_t handle, V value) override;

  MatchErrorCode get_value_(entry_handle_t handle, const V **value) override;

  MatchErrorCode get_entry_(entry_handle_t handle,
                            std::vector<MatchKeyParam> *match_key,
                            const V **value, int *priority) const override;

  MatchErrorCode dump_match_entry_(std::ostream *out,
                                   entry_handle_t handle) const override;

  void dump_(std::ostream *stream) const override;

  void reset_state_() override;

  MatchUnitLookup lookup_key(const ByteContainer &key) const override;

  bool has_rule(const ByteContainer &key, const ByteContainer &mask,
                int priority) const;

 private:
  std::vector<Entry> entries{};
};

}  // namespace bm

#endif  // BM_SIM_INCLUDE_BM_SIM_MATCH_UNITS_H_
