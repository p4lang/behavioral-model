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

#ifndef BM_BM_SIM_MATCH_TABLES_H_
#define BM_BM_SIM_MATCH_TABLES_H_

// shared_mutex will only be available in C++-14, so for now I'm using boost
#include <boost/thread/shared_mutex.hpp>

#include <vector>
#include <type_traits>
#include <iostream>
#include <string>

#include "match_units.h"
#include "actions.h"
#include "calculations.h"
#include "control_flow.h"
#include "lookup_structures.h"
#include "action_entry.h"
#include "action_profile.h"

namespace bm {

enum class MatchTableType {
  NONE = 0,
  SIMPLE,
  INDIRECT,
  INDIRECT_WS
};

class MatchTableAbstract : public NamedP4Object {
 public:
  friend class handle_iterator;

  using counter_value_t = Counter::counter_value_t;

  struct EntryCommon {
    entry_handle_t handle;
    std::vector<MatchKeyParam> match_key;
    uint32_t timeout_ms{0};
    uint32_t time_since_hit_ms{0};
  };

  class handle_iterator
      : public std::iterator<std::forward_iterator_tag, handle_t> {
   public:
    handle_iterator(const MatchTableAbstract *mt,
                    const MatchUnitAbstract_::handle_iterator &it)
        : mt(mt), it(it) { }

    const entry_handle_t &operator*() const {
      ReadLock lock = mt->lock_read();
      return *it;
    }

    const entry_handle_t *operator->() const {
      ReadLock lock = mt->lock_read();
      return it.operator->();
    }

    bool operator==(const handle_iterator &other) const {
      ReadLock lock = mt->lock_read();
      return (it == other.it);
    }

    bool operator!=(const handle_iterator &other) const {
      ReadLock lock = mt->lock_read();
      return !(*this == other);
    }

    handle_iterator &operator++() {
      ReadLock lock = mt->lock_read();
      it++;
      return *this;
    }

    const handle_iterator operator++(int) {
      // Use operator++()
      const handle_iterator old(*this);
      ++(*this);
      return old;
    }

   private:
    const MatchTableAbstract *mt;
    MatchUnitAbstract_::handle_iterator it;
  };

 public:
  MatchTableAbstract(const std::string &name, p4object_id_t id,
                     bool with_counters, bool with_ageing,
                     MatchUnitAbstract_ *mu);

  virtual ~MatchTableAbstract() { }

  const ControlFlowNode *apply_action(Packet *pkt);

  virtual MatchTableType get_table_type() const = 0;

  virtual const ActionEntry &lookup(const Packet &pkt, bool *hit,
                                    entry_handle_t *handle) = 0;

  virtual size_t get_num_entries() const = 0;

  virtual bool is_valid_handle(entry_handle_t handle) const = 0;

  MatchErrorCode dump_entry(std::ostream *out,
                            entry_handle_t handle) const {
    ReadLock lock = lock_read();
    return dump_entry_(out, handle);
  }

  std::string dump_entry_string(entry_handle_t handle) const {
    ReadLock lock = lock_read();
    return dump_entry_string_(handle);
  }

  void reset_state();

  void serialize(std::ostream *out) const;
  void deserialize(std::istream *in, const P4Objects &objs);

  void set_next_node(p4object_id_t action_id, const ControlFlowNode *next_node);
  void set_next_node_hit(const ControlFlowNode *next_node);
  // one of set_next_node_miss / set_next_node_miss_default has to be called
  // set_next_node_miss: if the P4 program has a table-action switch statement
  // with a 'miss' case
  // set_next_node_miss_default: in the general case
  // it is ok to call both, in which case set_next_node_miss will take priority
  void set_next_node_miss(const ControlFlowNode *next_node);
  void set_next_node_miss_default(const ControlFlowNode *next_node);

  void set_direct_meters(MeterArray *meter_array,
                         header_id_t target_header,
                         int target_offset);

  MatchErrorCode query_counters(entry_handle_t handle,
                                counter_value_t *bytes,
                                counter_value_t *packets) const;
  MatchErrorCode reset_counters();
  MatchErrorCode write_counters(entry_handle_t handle,
                                counter_value_t bytes,
                                counter_value_t packets);

  MatchErrorCode set_meter_rates(
      entry_handle_t handle,
      const std::vector<Meter::rate_config_t> &configs) const;

  MatchErrorCode get_meter_rates(
      entry_handle_t handle, std::vector<Meter::rate_config_t> *configs) const;

  MatchErrorCode set_entry_ttl(entry_handle_t handle, unsigned int ttl_ms);

  void sweep_entries(std::vector<entry_handle_t> *entries) const;

  handle_iterator handles_begin() const;
  handle_iterator handles_end() const;

  MatchTableAbstract(const MatchTableAbstract &other) = delete;
  MatchTableAbstract &operator=(const MatchTableAbstract &other) = delete;

  MatchTableAbstract(MatchTableAbstract &&other) = delete;
  MatchTableAbstract &operator=(MatchTableAbstract &&other) = delete;

 protected:
  using ReadLock = boost::shared_lock<boost::shared_mutex>;
  using WriteLock = boost::unique_lock<boost::shared_mutex>;

 protected:
  const ControlFlowNode *get_next_node(p4object_id_t action_id) const;
  const ControlFlowNode *get_next_node_default(p4object_id_t action_id) const;

  // assumes that entry->handle has been set
  void set_entry_common_info(EntryCommon *entry) const;

  ReadLock lock_read() const { return ReadLock(t_mutex); }
  WriteLock lock_write() const { return WriteLock(t_mutex); }

 protected:
  // Not sure these guys need to be atomic with the current code
  // TODO(antonin): check
  std::atomic_bool with_counters{false};
  std::atomic_bool with_meters{false};
  std::atomic_bool with_ageing{false};

  std::unordered_map<p4object_id_t, const ControlFlowNode *> next_nodes{};
  const ControlFlowNode *next_node_hit{nullptr};
  // next node if table is a miss
  const ControlFlowNode *next_node_miss{nullptr};
  // true if the P4 program explictly specified a table switch statement with a
  // "miss" case
  bool has_next_node_hit{false};
  bool has_next_node_miss{false};
  // stores default next node for miss case, used in case we want to reset a
  // table miss behavior
  const ControlFlowNode *next_node_miss_default{nullptr};

  header_id_t meter_target_header{};
  int meter_target_offset{};

 private:
  virtual void reset_state_() = 0;

  virtual void serialize_(std::ostream *out) const = 0;
  virtual void deserialize_(std::istream *in, const P4Objects &objs) = 0;

  virtual MatchErrorCode dump_entry_(std::ostream *out,
                                     entry_handle_t handle) const = 0;

  // the internal version does not acquire the lock
  std::string dump_entry_string_(entry_handle_t handle) const;

 private:
  mutable boost::shared_mutex t_mutex{};
  MatchUnitAbstract_ *match_unit_{nullptr};
};

// MatchTable is exposed to the runtime for configuration

class MatchTable : public MatchTableAbstract {
 public:
  struct Entry : public EntryCommon {
    const ActionFn *action_fn;
    ActionData action_data;
    int priority;
  };

 public:
  MatchTable(const std::string &name, p4object_id_t id,
             std::unique_ptr<MatchUnitAbstract<ActionEntry> > match_unit,
             bool with_counters = false, bool with_ageing = false);

  MatchErrorCode add_entry(const std::vector<MatchKeyParam> &match_key,
                           const ActionFn *action_fn,
                           ActionData action_data,  // move it
                           entry_handle_t *handle,
                           int priority = -1);

  MatchErrorCode delete_entry(entry_handle_t handle);

  MatchErrorCode modify_entry(entry_handle_t handle,
                              const ActionFn *action_fn,
                              ActionData action_data);

  MatchErrorCode set_default_action(const ActionFn *action_fn,
                                    ActionData action_data);

  MatchErrorCode get_entry(entry_handle_t handle, Entry *entry) const;

  MatchErrorCode get_entry_from_key(const std::vector<MatchKeyParam> &match_key,
                                    Entry *entry, int priority = 1) const;

  std::vector<Entry> get_entries() const;

  MatchErrorCode get_default_entry(Entry *entry) const;

  MatchTableType get_table_type() const override {
    return MatchTableType::SIMPLE;
  }

  const ActionEntry &lookup(const Packet &pkt, bool *hit,
                            entry_handle_t *handle) override;

  size_t get_num_entries() const override {
    return match_unit->get_num_entries();
  }

  bool is_valid_handle(entry_handle_t handle) const override {
    return match_unit->valid_handle(handle);
  }

  // meant to be called by P4Objects when loading the JSON
  // set_const_default_action_fn makes sure that the control plane cannot change
  // the default action; note that the action data can still be changed
  // set_default_entry sets a default entry obtained from the JSON. You can make
  // sure that neither the default action function nor the default action data
  // can be changed by the control plane by using the is_const parameter.
  void set_const_default_action_fn(const ActionFn *const_default_action_fn);
  void set_default_entry(const ActionFn *action_fn, ActionData action_data,
                         bool is_const);

 public:
  static std::unique_ptr<MatchTable> create(
      const std::string &match_type,
      const std::string &name,
      p4object_id_t id,
      size_t size, const MatchKeyBuilder &match_key_builder,
      LookupStructureFactory *lookup_factory,
      bool with_counters, bool with_ageing);

 private:
  void reset_state_() override;

  void serialize_(std::ostream *out) const override;
  void deserialize_(std::istream *in, const P4Objects &objs) override;

  MatchErrorCode dump_entry_(std::ostream *out,
                             entry_handle_t handle) const override;

  MatchErrorCode get_entry_(entry_handle_t handle, Entry *entry) const;

 private:
  ActionEntry default_entry{};
  std::unique_ptr<MatchUnitAbstract<ActionEntry> > match_unit;
  const ActionFn *const_default_action{nullptr};
  bool const_default_entry{false};
};

class MatchTableIndirect : public MatchTableAbstract {
 public:
  using mbr_hdl_t = ActionProfile::mbr_hdl_t;

  using IndirectIndex = ActionProfile::IndirectIndex;

  struct Entry : public EntryCommon {
    mbr_hdl_t mbr;
    int priority;
  };

 public:
  MatchTableIndirect(
      const std::string &name, p4object_id_t id,
      std::unique_ptr<MatchUnitAbstract<IndirectIndex> > match_unit,
      bool with_counters = false, bool with_ageing = false);

  void set_action_profile(ActionProfile *action_profile);

  MatchErrorCode add_entry(const std::vector<MatchKeyParam> &match_key,
                           mbr_hdl_t mbr,
                           entry_handle_t *handle,
                           int priority = -1);

  MatchErrorCode delete_entry(entry_handle_t handle);

  MatchErrorCode modify_entry(entry_handle_t handle, mbr_hdl_t mbr);

  MatchErrorCode set_default_member(mbr_hdl_t mbr);

  MatchErrorCode get_entry(entry_handle_t handle, Entry *entry) const;

  MatchErrorCode get_entry_from_key(const std::vector<MatchKeyParam> &match_key,
                                    Entry *entry, int priority = 1) const;

  std::vector<Entry> get_entries() const;

  MatchErrorCode get_default_entry(Entry *entry) const;

  MatchTableType get_table_type() const override {
    return MatchTableType::INDIRECT;
  }

  const ActionEntry &lookup(const Packet &pkt, bool *hit,
                            entry_handle_t *handle) override;

  size_t get_num_entries() const override {
    return match_unit->get_num_entries();
  }

  bool is_valid_handle(entry_handle_t handle) const override {
    return match_unit->valid_handle(handle);
  }

 public:
  static std::unique_ptr<MatchTableIndirect> create(
    const std::string &match_type,
    const std::string &name, p4object_id_t id,
    size_t size, const MatchKeyBuilder &match_key_builder,
    LookupStructureFactory *lookup_factory,
    bool with_counters, bool with_ageing);

 protected:
  void reset_state_() override;

  void serialize_(std::ostream *out) const override;
  void deserialize_(std::istream *in, const P4Objects &objs) override;

  void dump_(std::ostream *stream) const;

  MatchErrorCode dump_entry_(std::ostream *out,
                             entry_handle_t handle) const override;

  MatchErrorCode get_entry_(entry_handle_t handle, Entry *entry) const;

 protected:
  IndirectIndex default_index{};
  std::unique_ptr<MatchUnitAbstract<IndirectIndex> > match_unit;
  ActionProfile *action_profile{nullptr};
  bool default_set{false};
  ActionEntry empty_action{};
};

class MatchTableIndirectWS : public MatchTableIndirect {
 public:
  using grp_hdl_t = ActionProfile::grp_hdl_t;

  // If the entry points to a member, grp will be set to its maximum possible
  // value, i.e. std::numeric_limits<grp_hdl_t>::max(). If the entry points to a
  // group, it will be mbr that will be set to its max possible value.
  struct Entry : public EntryCommon {
    mbr_hdl_t mbr;
    grp_hdl_t grp;
    int priority;
  };

 public:
  MatchTableIndirectWS(
      const std::string &name, p4object_id_t id,
      std::unique_ptr<MatchUnitAbstract<IndirectIndex> > match_unit,
      bool with_counters = false, bool with_ageing = false);

  MatchErrorCode add_entry_ws(const std::vector<MatchKeyParam> &match_key,
                              grp_hdl_t grp,
                              entry_handle_t *handle,
                              int priority = -1);

  MatchErrorCode modify_entry_ws(entry_handle_t handle, grp_hdl_t grp);

  MatchErrorCode set_default_group(grp_hdl_t grp);

  MatchErrorCode get_entry(entry_handle_t handle, Entry *entry) const;

  MatchErrorCode get_entry_from_key(const std::vector<MatchKeyParam> &match_key,
                                    Entry *entry, int priority = 1) const;

  std::vector<Entry> get_entries() const;

  MatchErrorCode get_default_entry(Entry *entry) const;

  MatchTableType get_table_type() const override {
    return MatchTableType::INDIRECT_WS;
  }

  const ActionEntry &lookup(const Packet &pkt, bool *hit,
                            entry_handle_t *handle) override;

 public:
  static std::unique_ptr<MatchTableIndirectWS> create(
    const std::string &match_type,
    const std::string &name, p4object_id_t id,
    size_t size, const MatchKeyBuilder &match_key_builder,
    LookupStructureFactory *lookup_factory,
    bool with_counters, bool with_ageing);

 private:
  void reset_state_() override;

  void serialize_(std::ostream *out) const override;
  void deserialize_(std::istream *in, const P4Objects &objs) override;

  MatchErrorCode dump_entry_(std::ostream *out,
                            entry_handle_t handle) const override;

  MatchErrorCode get_entry_(entry_handle_t handle, Entry *entry) const;
};

}  // namespace bm

#endif  // BM_BM_SIM_MATCH_TABLES_H_
