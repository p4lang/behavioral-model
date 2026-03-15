/* Copyright 2018-present Barefoot Networks, Inc.
 * SPDX-License-Identifier: Apache-2.0
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

#include "digest_mgr.h"

#include <PI/pi_learn.h>

#include <chrono>
#include <exception>
#include <functional>  // for std::reference_wrapper
#include <future>
#include <memory>
#include <thread>
#include <tuple>  // for std::forward_as_tuple
#include <unordered_map>
#include <unordered_set>
#include <utility>  // for std::piecewise_construct
#include <vector>

#include "common.h"
#include "report_error.h"
#include "task_queue.h"

namespace p4v1 = ::p4::v1;
namespace p4configv1 = ::p4::config::v1;

namespace pi {

namespace fe {

namespace proto {

namespace {

namespace detail {

template <typename T> class Task : public TaskIface{
 public:
  explicit Task(T mgr)
      : mgr(mgr) { }

 protected:
  T mgr;
};

}  // namespace detail

using Task = detail::Task<DigestMgr *>;
using ConstTask = detail::Task<const DigestMgr *>;

using Status = DigestMgr::Status;
using Code = ::google::rpc::Code;
using EmptyPromise = std::promise<void>;
using StreamMessageResponseCb = DigestMgr::StreamMessageResponseCb;

using common::bytestring_pi_to_p4rt;

// Fowler–Noll–Vo hash function parameters depending on desired output size
// this ensures that things work correctly on both 32-bit and 64-bit systems
// when using fnv_1a_hash_params<size_t>
template <typename T, size_t S = sizeof(T)>
struct fnv_1a_hash_params;

template <typename T>
struct fnv_1a_hash_params<T, 4> {
  static constexpr T prime = 16777619u;
  static constexpr T offset = 0x811c9dc5u;
};

template <typename T>
struct fnv_1a_hash_params<T, 8> {
  static constexpr T prime = 1099511628211ull;
  static constexpr T offset = 0xcbf29ce484222325ull;
};

// Fowler–Noll–Vo hash function
struct fnv_1a_hash {
  size_t operator()(const char *data, size_t size) const {
    size_t hash = fnv_1a_hash_params<size_t>::offset;
    for (size_t i = 0; i < size; i++)
      hash = (hash ^ data[i]) * fnv_1a_hash_params<size_t>::prime;
    return hash;
  }
};

// Sample does not take ownership of any data; instead it holds a pointer to the
// entries array in pi_learn_msg_t. This way we avoid making copies of the data
// when inserting samples in the cache and it is convenient to do cache lookups
// for new pi_learn_msg_t messages.
struct Sample {
  Sample(const char *data, size_t size)
      : data(data), size(size) { }

  const char *data;
  size_t size;
};

struct SampleHash {
  size_t operator()(const Sample &s) const {
    return fnv_1a_hash()(s.data, s.size);
  }
};

struct SampleEq {
  size_t operator()(const Sample &lhs, const Sample &rhs) const {
    return (lhs.size == rhs.size) && !std::memcmp(lhs.data, rhs.data, lhs.size);
  }
};

// Functor interface to convert a Sample to a P4Data message which can be sent
// to the P4Runtime client. We currently support only very simple cases: P4
// structs with bitsting members, P4 tuples with bitsting members, and plain
// bitstrings.
// TODO(antonin): move these classes to their own file when adding support for
// Register, so that they can be re-used.
class TypeSpecConverterIface {
 public:
  virtual ~TypeSpecConverterIface() { }
  virtual void operator()(const Sample &s, p4v1::P4Data *p4_data) = 0;

  static std::unique_ptr<TypeSpecConverterIface> make(
      const p4configv1::P4DataTypeSpec &type_spec,
      const p4configv1::P4TypeInfo &type_info);
};

class TypeSpecConverterStruct : public TypeSpecConverterIface {
 public:
  void operator()(const Sample &s, p4v1::P4Data *p4_data) override;

  static std::unique_ptr<TypeSpecConverterIface> make(
      const p4configv1::P4NamedType &name,
      const p4configv1::P4TypeInfo &type_info);

 private:
  explicit TypeSpecConverterStruct(std::vector<size_t> &&bitwidths)
      : bitwidths(std::move(bitwidths)) { }

  // TODO(antonin): this could be changed to
  // std::vector<std::unique_ptr<TypeSpecConverterIface> > if we wanted to
  // support the more general case where the struct members are not
  // bitstrings. Howevever, at the moment I'm not aware of any compiler backend
  // that can handle the general case, so I'm making this assumption to avoid
  // extra overhead in the conversion.
  std::vector<size_t> bitwidths;
};

class TypeSpecConverterTuple : public TypeSpecConverterIface {
 public:
  void operator()(const Sample &s, p4v1::P4Data *p4_data) override;

  static std::unique_ptr<TypeSpecConverterIface> make(
      const p4configv1::P4TupleTypeSpec &type_spec,
      const p4configv1::P4TypeInfo &type_info);

 private:
  explicit TypeSpecConverterTuple(std::vector<size_t> &&bitwidths)
      : bitwidths(std::move(bitwidths)) { }

  std::vector<size_t> bitwidths;
};

class TypeSpecConverterBitstring : public TypeSpecConverterIface {
 public:
  void operator()(const Sample &s, p4v1::P4Data *p4_data) override;

  static std::unique_ptr<TypeSpecConverterIface> make(
      const p4configv1::P4BitstringLikeTypeSpec &type_spec);

 private:
  explicit TypeSpecConverterBitstring(size_t bitwidth)
      : bitwidth(bitwidth) { }

  size_t bitwidth;
};

// exception class used internally only to signal an unsupported packed type for
// the Digest instance
class type_spec_exception : std::exception {
 public:
  explicit type_spec_exception(Status status)
      : status_(std::move(status)) { }

  const char* what() const noexcept override {
    return status_.message().c_str();
  }

  const Status &status() const noexcept {
    return status_;
  }

 private:
  Status status_;
};

/* static */
std::unique_ptr<TypeSpecConverterIface>
TypeSpecConverterIface::make(const p4configv1::P4DataTypeSpec &type_spec,
                             const p4configv1::P4TypeInfo &type_info) {
  switch (type_spec.type_spec_case()) {
    case p4configv1::P4DataTypeSpec::kBitstring:
      return TypeSpecConverterBitstring::make(type_spec.bitstring());
    case p4configv1::P4DataTypeSpec::kTuple:
      return TypeSpecConverterTuple::make(type_spec.tuple(), type_info);
    case p4configv1::P4DataTypeSpec::kStruct:
      return TypeSpecConverterStruct::make(type_spec.struct_(), type_info);
    default:
      throw type_spec_exception(
          ERROR_STATUS(
              Code::UNIMPLEMENTED,
              "Packed type for digest can only be bitstring, struct or tuple"));
  }
  return nullptr;
}

/* static */
std::unique_ptr<TypeSpecConverterIface>
TypeSpecConverterStruct::make(const p4configv1::P4NamedType &name,
                              const p4configv1::P4TypeInfo &type_info) {
  std::vector<size_t> bitwidths;
  auto p_it = type_info.structs().find(name.name());
  if (p_it == type_info.structs().end()) {
    throw type_spec_exception(
        ERROR_STATUS(
            Code::INVALID_ARGUMENT,
            "Struct name '{}' name not found in P4TypeInfo struct map",
            name.name()));
  }
  for (const auto &member : p_it->second.members()) {
    if (!member.type_spec().has_bitstring()) {
      throw type_spec_exception(
          ERROR_STATUS(
              Code::UNIMPLEMENTED,
              "Struct can only include bistring members for digests"));
    }
    const auto &bitstring = member.type_spec().bitstring();
    if (bitstring.has_bit()) {
      bitwidths.push_back(bitstring.bit().bitwidth());
    } else if (bitstring.has_int_()) {
      bitwidths.push_back(bitstring.int_().bitwidth());
    } else {
      throw type_spec_exception(
          ERROR_STATUS(
              Code::UNIMPLEMENTED, "Varbits not supported for digests"));
    }
  }
  return std::unique_ptr<TypeSpecConverterIface>(
      new TypeSpecConverterStruct(std::move(bitwidths)));
}

void
TypeSpecConverterStruct::operator()(const Sample &s, p4v1::P4Data *p4_data) {
  size_t offset = 0;
  size_t bytes = 0;
  auto *struct_like = p4_data->mutable_struct_();
  for (const auto &bitwidth : bitwidths) {
    bytes = (bitwidth + 7) / 8;
    struct_like->add_members()->set_bitstring(
        bytestring_pi_to_p4rt(s.data + offset, bytes));
    offset += bytes;
  }
}

/* static */
std::unique_ptr<TypeSpecConverterIface>
TypeSpecConverterTuple::make(const p4configv1::P4TupleTypeSpec &type_spec,
                             const p4configv1::P4TypeInfo &type_info) {
  (void)type_info;
  std::vector<size_t> bitwidths;
  for (const auto &member : type_spec.members()) {
    if (!member.has_bitstring()) {
      throw type_spec_exception(
          ERROR_STATUS(
              Code::UNIMPLEMENTED,
              "Tuple can only include bistring members for digests"));
    }
    const auto &bitstring = member.bitstring();
    if (bitstring.has_bit()) {
      bitwidths.push_back(bitstring.bit().bitwidth());
    } else if (bitstring.has_int_()) {
      bitwidths.push_back(bitstring.int_().bitwidth());
    } else {
      throw type_spec_exception(
          ERROR_STATUS(
              Code::UNIMPLEMENTED, "Varbits not supported for digests"));
    }
  }
  return std::unique_ptr<TypeSpecConverterIface>(
      new TypeSpecConverterTuple(std::move(bitwidths)));
}

void
TypeSpecConverterTuple::operator()(const Sample &s, p4v1::P4Data *p4_data) {
  size_t offset = 0;
  size_t bytes = 0;
  auto *struct_like = p4_data->mutable_tuple();
  for (const auto &bitwidth : bitwidths) {
    bytes = (bitwidth + 7) / 8;
    struct_like->add_members()->set_bitstring(
        bytestring_pi_to_p4rt(s.data + offset, bytes));
    offset += bytes;
  }
}

/* static */
std::unique_ptr<TypeSpecConverterIface>
TypeSpecConverterBitstring::make(
    const p4configv1::P4BitstringLikeTypeSpec &type_spec) {
  size_t bitwidth;
  if (type_spec.has_bit()) {
    bitwidth = type_spec.bit().bitwidth();
  } else if (type_spec.has_int_()) {
    bitwidth = type_spec.int_().bitwidth();
  } else {
    throw type_spec_exception(
        ERROR_STATUS(
            Code::UNIMPLEMENTED, "Varbits not supported for digests"));
  }
  return std::unique_ptr<TypeSpecConverterIface>(
      new TypeSpecConverterBitstring(bitwidth));
}

void
TypeSpecConverterBitstring::operator()(const Sample &s, p4v1::P4Data *p4_data) {
  if (s.size != (bitwidth + 7) / 8) {
    Logger::get()->error(
        "Digest sample received from PI doesn't match expected format");
    return;
  }
  p4_data->set_bitstring(bytestring_pi_to_p4rt(s.data, s.size));
}

using Cache = std::unordered_set<Sample, SampleHash, SampleEq>;

struct ListData {
  using CachePointers =
      std::vector<std::reference_wrapper<const Cache::key_type> >;
  // References to cache entries that can be erased on the list / buffer is
  // acked by the P4Runtime client (or expires)
  CachePointers cache_pointers{};
  // Used to "expire" this digest list and remove the appropriate entries from
  // the cache. An asynchronous task is executed periodically (every
  // ack_timeout_ns). The first time the task sees this object, timeout_bit is
  // set to true. The second time, we expire the list.
  bool timeout_bit{false};
  // Takes ownership of the pi_learn_msg_t messages sent by the PI layer. When
  // the list is acked (or expires), these can be freed by calling
  // pi_learn_msg_done.
  std::vector<pi_learn_msg_t *> pi_msgs;
};

class DigestData {
 public:
  DigestData(DigestMgr::device_id_t device_id,
             DigestMgr::p4_id_t digest_id,
             std::unique_ptr<TypeSpecConverterIface> type_spec_converter,
             const StreamMessageResponseCb &cb,
             void *const &cookie)
      : device_id(device_id),
        type_spec_converter(std::move(type_spec_converter)),
        cb(cb), cookie(cookie) {
    digest.set_digest_id(digest_id);
    digest.set_list_id(1);
  }

  DigestData(const DigestData &) = delete;
  DigestData &operator=(const DigestData &) = delete;
  DigestData(DigestData &&) = delete;
  DigestData &operator=(DigestData &&) = delete;

  void purge_cache_if_needed() {
    auto it = list_id_to_data.begin();
    while (it != list_id_to_data.end()) {
      if (!it->second.timeout_bit) {
        it->second.timeout_bit = true;
        it++;
        continue;
      }
      purge_cache(it);
      it = list_id_to_data.erase(it);
    }
  }

  void ack(uint64_t list_id) {
    auto it = list_id_to_data.find(list_id);
    if (it == list_id_to_data.end()) return;
    purge_cache(it);
    list_id_to_data.erase(it);
  }

  void send_digest_if_needed() {
    if (digest.data_size() == 0) return;
    if (!timeout_bit) {
      timeout_bit = true;
      return;
    }
    send_digest();
  }

  uint64_t max_timeout_ns() const {
    return static_cast<uint64_t>(config.config().max_timeout_ns());
  }

  uint32_t max_list_size() const {
    return static_cast<uint32_t>(config.config().max_list_size());
  }

  uint64_t ack_timeout_ns() const {
    return static_cast<uint64_t>(config.config().ack_timeout_ns());
  }

  Status set_config(const p4v1::DigestEntry &entry, p4v1::Update::Type type) {
    if (type == p4v1::Update::INSERT) {
      if (config_set) {
        RETURN_ERROR_STATUS(Code::ALREADY_EXISTS,
                            "Digest {} already configured",
                            digest.digest_id());
      }
      config.CopyFrom(entry);
      config_set = true;
      RETURN_OK_STATUS();
    }
    if (type == p4v1::Update::MODIFY) {
      if (!config_set) {
        RETURN_ERROR_STATUS(
            Code::NOT_FOUND, "Digest {} not configured", digest.digest_id());
      }
      config.CopyFrom(entry);
      RETURN_OK_STATUS();
    }
    if (type == p4v1::Update::DELETE) {
      if (!config_set) {
        RETURN_ERROR_STATUS(
            Code::NOT_FOUND, "Digest {} not configured", digest.digest_id());
      }
      reset();
      RETURN_OK_STATUS();
    }
    RETURN_ERROR_STATUS(
        Code::INVALID_ARGUMENT, "Invalid update type for DigestEntry");
  }

  Status get_config(p4v1::ReadResponse *response) const {
    if (!config_set) {
      RETURN_ERROR_STATUS(
          Code::NOT_FOUND, "Digest {} not configured", digest.digest_id());
    }
    response->add_entities()->mutable_digest_entry()->CopyFrom(config);
    RETURN_OK_STATUS();
  }

  void learn(pi_learn_msg_t *msg) {
    if (!cb || !config_set) {
      pi_learn_msg_done(msg);
      return;
    }
    auto &data = current_list_data;
    bool new_entries_added_to_digest = false;
    bool new_entries_added_to_cache = false;
    for (size_t i = 0; i < msg->num_entries; i++) {
      Sample s(msg->entries + (i * msg->entry_size), msg->entry_size);
      if (ack_timeout_ns() > 0) {  // don't use cache if ack_timeout_ns is 0
        auto p = cache.insert(s);
        if (!p.second) continue;
        data.cache_pointers.emplace_back(*p.first);
        new_entries_added_to_cache = true;
      }
      add_to_digest(s);
      new_entries_added_to_digest = true;
    }
    if (new_entries_added_to_cache)
      data.pi_msgs.push_back(msg);
    else
      pi_learn_msg_done(msg);
    if (!new_entries_added_to_digest) return;
    if ((max_list_size() != 0 &&
         data.cache_pointers.size() >= max_list_size()) ||
        max_timeout_ns() == 0) {
      send_digest();
    }
  }

 private:
  void add_to_digest(const Sample &s) {
    (*type_spec_converter)(s, digest.add_data());
  }

  void purge_cache(std::unordered_map<uint64_t, ListData>::iterator it) {
    for (const auto &ptr : it->second.cache_pointers)
      cache.erase(ptr);
    for (auto pi_msg : it->second.pi_msgs)
      pi_learn_msg_done(pi_msg);
  }

  void send_digest() {
    using Clock = std::chrono::steady_clock;
    p4v1::StreamMessageResponse response;
    digest.set_timestamp(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now().time_since_epoch()).count());
    // the test for a callback is probably not strictly required based on our
    // usage. However, in theory it is possible for the callback to be
    // unregistered and then have the timeout sweep task try to generate a
    // digest message.
    if (cb) {
        response.unsafe_arena_set_allocated_digest(&digest);
        cb(device_id, &response, cookie);
        response.unsafe_arena_release_digest();
    }
    timeout_bit = false;
    // for the case where ack_timeout_ns is 0 and no caching is done
    if (!current_list_data.cache_pointers.empty())
      list_id_to_data.emplace(digest.list_id(), std::move(current_list_data));
    current_list_data = {};
    digest.set_list_id(digest.list_id() + 1);
    digest.clear_data();
  }

  void reset() {
    config.Clear();
    config_set = false;
    for (auto it = list_id_to_data.begin(); it != list_id_to_data.end(); it++)
      purge_cache(it);
    assert(cache.empty());
    list_id_to_data.clear();
    // digest.set_list_id(1);
    digest.clear_data();
    current_list_data = {};
    timeout_bit = false;
  }

  DigestMgr::device_id_t device_id;
  std::unique_ptr<TypeSpecConverterIface> type_spec_converter;
  const StreamMessageResponseCb &cb;
  void *const &cookie;  // const reference to a void *
  p4v1::DigestEntry config{};
  bool config_set{false};
  Cache cache{};
  std::unordered_map<uint64_t, ListData> list_id_to_data{};
  p4v1::DigestList digest{};  // message being built
  ListData current_list_data{};
  bool timeout_bit{false};
};

}  // namespace

// includes all the "state" for the DigestMgr instance
class DigestMgr::State {
 public:
  using iterator = std::unordered_map<p4_id_t, DigestData>::iterator;
  using const_iterator =
      std::unordered_map<p4_id_t, DigestData>::const_iterator;

  State(device_id_t device_id,
        const StreamMessageResponseCb &cb,
        void *const &cookie)
      : device_id(device_id), cb(cb), cookie(cookie) { }

  void emplace_digest(
      const p4configv1::Digest &digest,
      std::unique_ptr<TypeSpecConverterIface> type_spec_converter) {
    auto digest_id = digest.preamble().id();
    digests.emplace(
        std::piecewise_construct,  // DigestData non copy constructible
        std::forward_as_tuple(digest_id),
        std::forward_as_tuple(
            device_id, digest_id, std::move(type_spec_converter), cb, cookie));
  }

  DigestData &at(p4_id_t digest_id) {
    return digests.at(digest_id);
  }
  const DigestData &at(p4_id_t digest_id) const {
    return digests.at(digest_id);
  }

  iterator find(p4_id_t digest_id) {
    return digests.find(digest_id);
  }
  const_iterator find(p4_id_t digest_id) const {
    return digests.find(digest_id);
  }

  iterator begin() {
    return digests.begin();
  }
  const_iterator cbegin() const {
    return digests.cbegin();
  }

  iterator end() {
    return digests.end();
  }
  const_iterator cend() const {
    return digests.cend();
  }

 private:
  device_id_t device_id;
  const StreamMessageResponseCb &cb;
  void *const &cookie;
  std::unordered_map<p4_id_t, DigestData> digests;
};

// For each digest, we have potentially 2 periodic tasks doing sweeps: one to
// enforce max_timeout_ns (a sample should not be buffered for more than
// max_timeout_ns), and one to enforce ack_timeout_ns (a cache entry should be
// cleared if unacked for more than ack_timeout_ns). The current implementation
// is not very accurate. For each task, we use a boolean flag which is flipped
// on the first time the task visits the object. The second time the object is
// visited, the task action is performed.
// In the default configuration (max_timeout_ns = 0 / ack_timeout_ns = 0), there
// is no sweep being performed (i.e. task is not scheduled).
class DigestMgr::SweepTasks {
 public:
  SweepTasks(DigestMgr *mgr, const p4configv1::P4Info &p4info) {
    for (const auto &digest : p4info.digests()) {
      auto digest_id = digest.preamble().id();
      tasks.emplace(digest_id, Tasks(mgr, digest_id));
    }
  }

  SweepTasks(const SweepTasks &) = delete;
  SweepTasks &operator=(const SweepTasks &) = delete;
  SweepTasks(SweepTasks &&) = delete;
  SweepTasks &operator=(SweepTasks &&) = delete;

  void set_max_timeout_ns(p4_id_t digest_id, int64_t max_timeout_ns) {
    tasks.at(digest_id).set_max_timeout_ns(max_timeout_ns);
  }

  void set_ack_timeout_ns(p4_id_t digest_id, int64_t ack_timeout_ns) {
    tasks.at(digest_id).set_ack_timeout_ns(ack_timeout_ns);
  }

  void set_config(const p4v1::DigestEntry &entry, p4v1::Update::Type type) {
    auto &t = tasks.at(entry.digest_id());
    if (type == p4v1::Update::INSERT || type == p4v1::Update::MODIFY) {
      t.set_max_timeout_ns(entry.config().max_timeout_ns());
      t.set_ack_timeout_ns(entry.config().ack_timeout_ns());
    } else if (type == p4v1::Update::DELETE) {
      t.cancel();
    }
  }

 private:
  struct TaskAckTimeout : public CancellableTask {
   public:
    explicit TaskAckTimeout(DigestData *digest_data)
        : digest_data(digest_data) { }

    void operator()() override {
      digest_data->purge_cache_if_needed();
    }

   private:
    DigestData *digest_data;
  };

  struct TaskMaxTimeout : public CancellableTask {
   public:
    explicit TaskMaxTimeout(DigestData *digest_data)
        : digest_data(digest_data) { }

    void operator()() override {
      digest_data->send_digest_if_needed();
    }

   private:
    DigestData *digest_data;
  };

  class Tasks {
   public:
    Tasks(DigestMgr *mgr, DigestMgr::p4_id_t digest_id)
        : mgr(mgr), digest_id(digest_id), task_queue(mgr->task_queue.get()) { }

    ~Tasks() {
      cancel();
    }

    void cancel() {
      if (task_ack_timeout) {
        task_ack_timeout->cancel();
        task_ack_timeout = nullptr;
      }
      if (task_max_timeout) {
        task_max_timeout->cancel();
        task_ack_timeout = nullptr;
      }
    }

    void set_max_timeout_ns(int64_t max_timeout_ns) {
      if (task_max_timeout) task_max_timeout->cancel();
      if (max_timeout_ns == 0) return;
      if (max_timeout_ns < min_max_timeout_ns)
        max_timeout_ns = min_max_timeout_ns;
      auto &digest_data = mgr->state->at(digest_id);
      task_max_timeout = new TaskMaxTimeout(&digest_data);
      task_queue->execute_periodic_task(
          std::unique_ptr<TaskIface>(task_max_timeout),
          std::chrono::nanoseconds(max_timeout_ns),
          true  /* wait_first */);
    }

    void set_ack_timeout_ns(int64_t ack_timeout_ns) {
      if (task_ack_timeout) task_ack_timeout->cancel();
      if (ack_timeout_ns == 0) return;
      if (ack_timeout_ns < min_ack_timeout_ns)
        ack_timeout_ns = min_ack_timeout_ns;
      auto &digest_data = mgr->state->at(digest_id);
      task_ack_timeout = new TaskAckTimeout(&digest_data);
      task_queue->execute_periodic_task(
          std::unique_ptr<TaskIface>(task_ack_timeout),
          std::chrono::nanoseconds(ack_timeout_ns),
          true  /* wait_first */);
    }

   private:
    static constexpr int64_t min_max_timeout_ns = 100000000;  // 100ms
    static constexpr int64_t min_ack_timeout_ns = 100000000;  // 100ms
    DigestMgr *mgr;
    DigestMgr::p4_id_t digest_id;
    DigestTaskQueue *task_queue;
    TaskAckTimeout *task_ack_timeout{nullptr};
    TaskMaxTimeout *task_max_timeout{nullptr};
  };

 private:
  std::unordered_map<p4_id_t, Tasks> tasks{};
};

DigestMgr::DigestMgr(device_id_t device_id)
    : device_id(device_id),
      task_queue(new DigestTaskQueue()),
      state(nullptr),
      sweep_tasks(nullptr) {
  // We use an asynchronous task queue for all tasks that need to touch the
  // shared state. This task queue is served by a single dedicated thread which
  // is why you won't see any mutex in this code. Because our task queue only
  // accepts functors (which implement TaskIface) and not lambdas, some of the
  // task definitions are a bit verbose.
  // I make no claim that this design is better than a synchronous one. As it
  // stands the task that performs the learning may get stuck on the Write call
  // to the stream. Maybe a better design would be to introduce another
  // asynchronous task queue for writing to the stream (in the server
  // code). Regardless, this code was fun to write.
  task_queue_thread = std::thread(&DigestTaskQueue::execute, task_queue.get());
  pi_learn_register_cb(device_id, &DigestMgr::digest_cb, this);
}

DigestMgr::~DigestMgr() {
  pi_learn_deregister_cb(device_id);
  task_queue->stop();
  task_queue_thread.join();
}

// We assume that by the time the call to p4_change completes, we can no longer
// receive notifications for the old dataplane from PI. Note that p4_change is
// called after pi_update_device_start returns. Targets should take this into
// account and should not generate notifications for the old dataplane after
// pi_update_device_start returns. This should not proved too hard to achieve
// but if we run into issues, we can always add a new API to DigestMgr to be
// called after pi_update_device_end returns. DigestMgr will ignore all
// notifications received between pi_update_device_start and
// pi_update_device_end.
Status
DigestMgr::p4_change(const p4configv1::P4Info &p4info) {
  class TaskP4Change : public Task {
   public:
    TaskP4Change(DigestMgr *mgr,
                 std::unique_ptr<State> new_state,
                 std::unique_ptr<SweepTasks> new_sweep_tasks,
                 EmptyPromise &promise)  // NOLINT(runtime/references)
        : Task(mgr),
          new_state(std::move(new_state)),
          new_sweep_tasks(std::move(new_sweep_tasks)),
          promise(promise) { }

    void operator()() override {
      mgr->state = std::move(new_state);
      mgr->sweep_tasks = std::move(new_sweep_tasks);
      promise.set_value();
    }

   private:
    std::unique_ptr<State> new_state;
    std::unique_ptr<SweepTasks> new_sweep_tasks;
    EmptyPromise &promise;
  };

  // First build the new state, then perform the swap in an asynchronous task.
  std::unique_ptr<State> new_state(new State(device_id, cb, cookie));
  for (const auto &digest : p4info.digests()) {
    try {
      auto type_spec_converter = TypeSpecConverterIface::make(
          digest.type_spec(), p4info.type_info());
      new_state->emplace_digest(digest, std::move(type_spec_converter));
    } catch (const type_spec_exception &e) {
      return e.status();
    }
  }
  std::unique_ptr<SweepTasks> new_sweep_tasks(new SweepTasks(this, p4info));
  EmptyPromise promise;
  task_queue->execute_task(std::unique_ptr<TaskIface>(
      new TaskP4Change(
          this, std::move(new_state), std::move(new_sweep_tasks), promise)));
  promise.get_future().wait();
  RETURN_OK_STATUS();
}

Status
DigestMgr::config_write(const p4v1::DigestEntry &entry,
                        p4v1::Update::Type type,
                        const common::SessionTemp &session) {
  class TaskConfigWrite : public Task {
   public:
    TaskConfigWrite(DigestMgr *mgr,
                    const p4v1::DigestEntry &entry,
                    p4v1::Update::Type type,
                    std::promise<Status> &status)  // NOLINT(runtime/references)
        : Task(mgr), entry(entry), type(type), status(status) { }

    void operator()() {
      auto it = mgr->state->find(entry.digest_id());
      if (it == mgr->state->end()) {
        status.set_value(ERROR_STATUS(
            Code::NOT_FOUND, "{} is not a valid digest id", entry.digest_id()));
        return;
      }
      {
        auto s = it->second.set_config(entry, type);
        if (IS_ERROR(s)) {
          status.set_value(s);
          return;
        }
      }
      mgr->sweep_tasks->set_config(entry, type);
      status.set_value(OK_STATUS());
    }

   private:
    const p4v1::DigestEntry &entry;
    const p4v1::Update::Type type;
    std::promise<Status> &status;
  };

  std::promise<Status> promise;
  auto future = promise.get_future();
  task_queue->execute_task(std::unique_ptr<TaskIface>(
      new TaskConfigWrite(this, entry, type, promise)));
  future.wait();
  auto status = future.get();
  if (IS_ERROR(status)) return status;
  if (type == p4v1::Update::INSERT || type == p4v1::Update::MODIFY) {
    pi_learn_config_t pi_config;
    pi_config.max_size = entry.config().max_list_size();
    pi_config.max_timeout_ns = entry.config().max_timeout_ns();
    auto pi_status = pi_learn_config_set(
        session.get(), device_id, entry.digest_id(), &pi_config);
    if (pi_status != PI_STATUS_SUCCESS)
      RETURN_ERROR_STATUS(Code::INTERNAL,
                          "Error when configuring digest with target");
  } else if (type == p4v1::Update::DELETE) {
    auto pi_status = pi_learn_config_set(
        session.get(), device_id, entry.digest_id(), nullptr);
    if (pi_status != PI_STATUS_SUCCESS)
      RETURN_ERROR_STATUS(Code::INTERNAL,
                          "Error when disabling digest with target");
  }
  RETURN_OK_STATUS();
}

Status
DigestMgr::config_read(const p4::v1::DigestEntry &entry,
                       p4v1::ReadResponse *response) const {
  class TaskConfigRead : public ConstTask {
   public:
    TaskConfigRead(const DigestMgr *mgr,
                   p4_id_t digest_id,
                   p4v1::ReadResponse *response,
                   std::promise<Status> &status)  // NOLINT(runtime/references)
        : Task(mgr), digest_id(digest_id), response(response),
          status(status) { }

    void operator()() {
      auto it = mgr->state->find(digest_id);
      if (it == mgr->state->end()) {
        status.set_value(ERROR_STATUS(
            Code::NOT_FOUND, "{} is not a valid digest id", digest_id));
        return;
      }
      status.set_value(it->second.get_config(response));
    }

   private:
    p4_id_t digest_id;
    p4v1::ReadResponse *response;
    std::promise<Status> &status;
  };

  if (entry.digest_id() == 0) {
    RETURN_ERROR_STATUS(Code::UNIMPLEMENTED,
                        "digest_id must be set when reading DigestEntry");
  }
  std::promise<Status> promise;
  auto future = promise.get_future();
  task_queue->execute_task(std::unique_ptr<TaskIface>(
      new TaskConfigRead(this, entry.digest_id(), response, promise)));
  future.wait();
  return future.get();
}

void
DigestMgr::ack(const p4v1::DigestListAck &ack) {
  class TaskAck : public Task {
   public:
    TaskAck(DigestMgr *mgr,
            const p4v1::DigestListAck &ack)
        : Task(mgr), ack(ack) { }

    void operator()() {
      auto it = mgr->state->find(ack.digest_id());
      if (it == mgr->state->end()) return;
      it->second.ack(ack.list_id());
    }

   private:
    const p4v1::DigestListAck &ack;
  };

  // we do not care about completion for this task
  task_queue->execute_task(std::unique_ptr<TaskIface>(new TaskAck(this, ack)));
}

void
DigestMgr::stream_message_response_register_cb(StreamMessageResponseCb cb,
                                               void *cookie) {
  class TaskRegisterCb : public Task {
   public:
    TaskRegisterCb(DigestMgr *mgr,
                   EmptyPromise &promise,  // NOLINT(runtime/references)
                   // NOLINTNEXTLINE(whitespace/operators)
                   StreamMessageResponseCb &&cb,
                   void *cookie)
        : Task(mgr), promise(promise), cb(std::move(cb)), cookie(cookie) { }

    void operator()() override {
      mgr->cb = std::move(cb);
      mgr->cookie = std::move(cookie);
      promise.set_value();
    }

   private:
    EmptyPromise &promise;
    StreamMessageResponseCb &&cb;
    void *cookie;
  };

  EmptyPromise promise;
  task_queue->execute_task(std::unique_ptr<TaskIface>(new TaskRegisterCb(
      this, promise, std::move(cb), cookie)));
  promise.get_future().wait();
}

void
DigestMgr::stream_message_response_unregister_cb() {
  class TaskUnregisterCb : public Task {
   public:
    // NOLINTNEXTLINE(runtime/references)
    TaskUnregisterCb(DigestMgr *mgr, EmptyPromise &promise)
        : Task(mgr), promise(promise) { }

    void operator()() override {
      mgr->cb = nullptr;
      mgr->cookie = nullptr;
      promise.set_value();
    }

   private:
    EmptyPromise &promise;
  };

  EmptyPromise promise;
  task_queue->execute_task(std::unique_ptr<TaskIface>(new TaskUnregisterCb(
      this, promise)));
  promise.get_future().wait();
}

/* static */ void
DigestMgr::digest_cb(pi_learn_msg_t *msg, void *cookie) {
  auto *mgr = static_cast<DigestMgr *>(cookie);
  assert(mgr->device_id == msg->dev_tgt.dev_id);

  class TaskNewDigest : public Task {
   public:
    TaskNewDigest(DigestMgr *mgr, pi_learn_msg_t *msg)
        : Task(mgr), msg(msg) { }

    void operator()() override {
      common::SessionTemp session;
      auto &digest_data = mgr->state->at(msg->learn_id);
      // we could call pi_learn_msg_ack after calling learn() although it
      // shouldn't make much of a difference. If we switch the order of the
      // calls, we will need to copy msg->device_id, msg->learn_id and
      // msg->msg_id since learn() takes ownership of msg and may decide to free
      // it early.
      pi_learn_msg_ack(
          session.get(), mgr->device_id, msg->learn_id, msg->msg_id);
      digest_data.learn(msg);  // takes ownership of msg
    }

   private:
    pi_learn_msg_t *msg;
  };

  // do not wait for completion of the task
  mgr->task_queue->execute_task(std::unique_ptr<TaskIface>(new TaskNewDigest(
      mgr, msg)));
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
