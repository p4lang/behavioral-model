/* Copyright 2019-present Barefoot Networks, Inc.
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

#include "idle_timeout_buffer.h"

#include <PI/frontends/cpp/tables.h>

#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <unordered_map>
#include <utility>

#include "match_key_helpers.h"
#include "report_error.h"
#include "task_queue.h"

namespace pi {

namespace fe {

namespace proto {

namespace p4v1 = ::p4::v1;

namespace {

namespace detail {

template <typename T> class Task : public TaskIface{
 public:
  explicit Task(T buffer)
      : buffer(buffer) { }

 protected:
  T buffer;
};

}  // namespace detail

using Task = detail::Task<IdleTimeoutBuffer *>;
// not used for now
// using ConstTask = detail::Task<const IdleTimeoutBuffer *>;

using EmptyPromise = std::promise<void>;

using p4_id_t = common::p4_id_t;

}  // namespace

class IdleTimeoutBuffer::TaskSendNotifications : public Task {
 public:
  explicit TaskSendNotifications(IdleTimeoutBuffer *buffer)
      : Task(buffer) { }

  void operator()() override {
    using Clock = std::chrono::steady_clock;
    auto &notifications = buffer->notifications;
    if (notifications.table_entry().empty() || !buffer->cb) return;
    notifications.set_timestamp(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now().time_since_epoch()).count());
    p4v1::StreamMessageResponse msg;
    msg.unsafe_arena_set_allocated_idle_timeout_notification(&notifications);
    buffer->cb(buffer->device_id, &msg, buffer->cookie);
    msg.unsafe_arena_release_idle_timeout_notification();
    notifications.Clear();
  }
};

class IdleTimeoutBuffer::TableInfoStore {
 public:
  TableInfoStore() = default;
  ~TableInfoStore() = default;

  struct Data {
    uint64_t controller_metadata;
    int64_t idle_timeout_ns;
  };

  using TableInfoStoreOne =
      std::unordered_map<pi::MatchKey, Data, pi::MatchKeyHash, pi::MatchKeyEq>;

  void reset() {
    tables.clear();
  }

  TableInfoStoreOne *get(pi_p4_id_t t_id) {
    auto it = tables.find(t_id);
    return (it == tables.end()) ? nullptr : &it->second;
  }

  const TableInfoStoreOne *get(pi_p4_id_t t_id) const {
    auto it = tables.find(t_id);
    return (it == tables.end()) ? nullptr : &it->second;
  }

  void add_table(pi_p4_id_t t_id) {
    tables.emplace(t_id, TableInfoStoreOne());
  }

  Data *get_entry(pi_p4_id_t t_id, const pi::MatchKey &mk) {
    auto &table = tables.at(t_id);
    auto it = table.find(mk);
    return (it == table.end()) ? nullptr : &it->second;
  }

 private:
  std::unordered_map<pi_p4_id_t, TableInfoStoreOne> tables;
};

IdleTimeoutBuffer::IdleTimeoutBuffer(device_id_t device_id,
                                     int64_t max_buffering_ns)
    : device_id(device_id),
      table_info_store(new TableInfoStore()),
      max_buffering_ns(max_buffering_ns),
      task_queue(new IdleTimeoutTaskQueue()) {
  task_queue_thread = std::thread(
      &IdleTimeoutTaskQueue::execute, task_queue.get());
}

IdleTimeoutBuffer::~IdleTimeoutBuffer() {
  task_queue->stop();
  task_queue_thread.join();
}

// We assume that no notifications are received after the p4_change call
// completes. Note that p4_change is called after pi_update_device_start
// returns. Targets should take this into account and should not generate
// notifications for the old dataplane after pi_update_device_start returns.
// This guarantees that the stored p4info pointer is always valid.
Status
IdleTimeoutBuffer::p4_change(const pi_p4info_t *p4info) {
  class TaskP4Change : public Task {
   public:
    TaskP4Change(IdleTimeoutBuffer *buffer,
                 const pi_p4info_t *p4info,
                 EmptyPromise &promise)  // NOLINT(runtime/references)
        : Task(buffer), p4info(p4info), promise(promise) { }

    void operator()() override {
      // drain notifications for old P4
      TaskSendNotifications sender(buffer);
      sender();
      buffer->p4info = p4info;

      auto *table_info_store = buffer->table_info_store.get();
      table_info_store->reset();
      for (auto t_id = pi_p4info_table_begin(p4info);
           t_id != pi_p4info_table_end(p4info);
           t_id = pi_p4info_table_next(p4info, t_id)) {
        if (!pi_p4info_table_supports_idle_timeout(p4info, t_id)) continue;
        table_info_store->add_table(t_id);
      }

      promise.set_value();
    }

   private:
    const pi_p4info_t *p4info;
    EmptyPromise &promise;
  };

  EmptyPromise promise;
  task_queue->execute_task(std::unique_ptr<TaskIface>(
      new TaskP4Change(this, p4info, promise)));
  promise.get_future().wait();
  RETURN_OK_STATUS();
}

Status
IdleTimeoutBuffer::insert_entry(const pi::MatchKey &mk,
                                const p4v1::TableEntry &entry) {
  class TaskInsertEntry : public TaskIface {
   public:
    TaskInsertEntry(TableInfoStore *table_info_store,
                    const pi::MatchKey &mk,
                    const p4v1::TableEntry &entry)
        : table_info_store(table_info_store), mk(mk),
          data{entry.controller_metadata(), entry.idle_timeout_ns()} { }

    void operator()() override {
      auto t_id = mk.get_table_id();
      auto store = table_info_store->get(t_id);
      if (!store) {
        Logger::get()->error(
            "IdleTimeoutBuffer: cannot find table {} in store", t_id);
        return;
      }
      auto r = store->insert(std::make_pair(std::move(mk), data));
      if (!r.second) {
        Logger::get()->warn(
            "IdleTimeoutBuffer: trying to insert entry which already exists "
            "in store for table {}", t_id);
      }
    }

   private:
    TableInfoStore *table_info_store;
    pi::MatchKey mk;
    TableInfoStore::Data data;
  };

  task_queue->execute_task(std::unique_ptr<TaskIface>(
      new TaskInsertEntry(table_info_store.get(), mk, entry)));
  RETURN_OK_STATUS();
}

Status
IdleTimeoutBuffer::modify_entry(const pi::MatchKey &mk,
                                const p4v1::TableEntry &entry) {
  class TaskModifyEntry : public TaskIface {
   public:
    TaskModifyEntry(TableInfoStore *table_info_store,
                    const pi::MatchKey &mk,
                    const p4v1::TableEntry &entry)
        : table_info_store(table_info_store), mk(mk),
          data{entry.controller_metadata(), entry.idle_timeout_ns()} { }

    void operator()() override {
      auto t_id = mk.get_table_id();
      auto store = table_info_store->get(t_id);
      if (!store) {
        Logger::get()->error(
            "IdleTimeoutBuffer: cannot find table {} in store", t_id);
        return;
      }
      auto it = store->find(mk);
      if (it == store->end()) {
        Logger::get()->warn(
            "IdleTimeoutBuffer: trying to modify entry which does not exist "
            "in store for table {}", t_id);
        return;
      }
      it->second = data;
    }

   private:
    TableInfoStore *table_info_store;
    pi::MatchKey mk;
    TableInfoStore::Data data;
  };

  task_queue->execute_task(std::unique_ptr<TaskIface>(
      new TaskModifyEntry(table_info_store.get(), mk, entry)));
  RETURN_OK_STATUS();
}

Status
IdleTimeoutBuffer::delete_entry(const pi::MatchKey &mk) {
  class TaskDeleteEntry : public TaskIface {
   public:
    TaskDeleteEntry(TableInfoStore *table_info_store,
                    const pi::MatchKey &mk)
        : table_info_store(table_info_store), mk(mk) { }

    void operator()() override {
      auto t_id = mk.get_table_id();
      auto store = table_info_store->get(t_id);
      if (!store) {
        Logger::get()->error(
            "IdleTimeoutBuffer: cannot find table {} in store", t_id);
        return;
      }
      auto c = store->erase(mk);
      if (c == 0) {
        Logger::get()->warn(
            "IdleTimeoutBuffer: trying to delete entry which does not exist "
            "in store for table {}", t_id);
      }
    }

   private:
    TableInfoStore *table_info_store;
    pi::MatchKey mk;
  };

  task_queue->execute_task(std::unique_ptr<TaskIface>(
      new TaskDeleteEntry(table_info_store.get(), mk)));
  RETURN_OK_STATUS();
}

void
IdleTimeoutBuffer::stream_message_response_register_cb(
    StreamMessageResponseCb cb, void *cookie) {
  class TaskRegisterCb : public Task {
   public:
    TaskRegisterCb(IdleTimeoutBuffer *buffer,
                   EmptyPromise &promise,  // NOLINT(runtime/references)
                   // NOLINTNEXTLINE(whitespace/operators)
                   StreamMessageResponseCb &&cb,
                   void *cookie)
        : Task(buffer), promise(promise), cb(std::move(cb)), cookie(cookie) { }

    void operator()() override {
      buffer->cb = std::move(cb);
      buffer->cookie = std::move(cookie);
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
IdleTimeoutBuffer::handle_notification(p4_id_t table_id,
                                       pi::MatchKey match_key) {
  class TaskHandleNotification : public Task {
   public:
    TaskHandleNotification(IdleTimeoutBuffer *buffer,
                           p4_id_t table_id,
                           pi::MatchKey match_key)
      : Task(buffer), table_id(table_id), match_key(std::move(match_key)) { }

    void operator()() override {
      auto &notifications = buffer->notifications;
      bool first_notification = notifications.table_entry().empty();
      auto *table_entry = notifications.add_table_entry();
      table_entry->set_table_id(table_id);
      auto *entry_data = buffer->table_info_store->get_entry(
          table_id, match_key);
      if (entry_data == nullptr) {
        Logger::get()->warn("Failed to locate match key from idle timeout "
                             "notification in table info store");
        notifications.mutable_table_entry()->RemoveLast();
        return;
      }
      table_entry->set_controller_metadata(entry_data->controller_metadata);
      table_entry->set_idle_timeout_ns(entry_data->idle_timeout_ns);
      // simple sanity check: we should not be generating notifications for
      // entries which don't age.
      if (table_entry->idle_timeout_ns() == 0) {
        notifications.mutable_table_entry()->RemoveLast();
        return;
      }
      auto status = parse_match_key(
          buffer->p4info, table_id, match_key, table_entry);
      if (IS_ERROR(status)) {
        Logger::get()->error(
            "Failed to convert match key "
            "when generating idle timeout notification");
          notifications.mutable_table_entry()->RemoveLast();
        return;
      }
      if (first_notification) {
        buffer->task_queue->execute_task_in(
            std::unique_ptr<TaskIface>(new TaskSendNotifications(buffer)),
            std::chrono::nanoseconds(buffer->max_buffering_ns));
      }
    }

   private:
    p4_id_t table_id;
    pi::MatchKey match_key;
  };

  // non-blocking
  size_t count = task_queue->execute_task_or_drop(
      std::unique_ptr<TaskIface>(
          new TaskHandleNotification(this, table_id, std::move(match_key))),
      max_queue_size);
  if (count == 0) {
    Logger::get()->debug(
        "Dropping idle time notification for table {} because queue is full",
        table_id);
    drop_count++;
  }
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
