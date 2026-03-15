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

#ifndef SRC_IDLE_TIMEOUT_BUFFER_H_
#define SRC_IDLE_TIMEOUT_BUFFER_H_

#include <PI/frontends/cpp/tables.h>
#include <PI/frontends/proto/device_mgr.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

#include "google/rpc/status.pb.h"
#include "p4/v1/p4runtime.pb.h"

#include "common.h"

namespace pi {

namespace fe {

namespace proto {

template <typename Clock> class TaskQueue;
using IdleTimeoutTaskQueue = TaskQueue<std::chrono::steady_clock>;

class IdleTimeoutBuffer {
 public:
  using device_id_t = DeviceMgr::device_id_t;
  using StreamMessageResponseCb = DeviceMgr::StreamMessageResponseCb;

  static constexpr int64_t kDefaultMaxBufferingNs = 100 * 1000 * 1000;  // 100ms

  IdleTimeoutBuffer(device_id_t device_id,
                    int64_t max_buffering_ns = kDefaultMaxBufferingNs);

  ~IdleTimeoutBuffer();

  Status p4_change(const pi_p4info_t *p4info);

  Status insert_entry(const pi::MatchKey &mk,
                      const ::p4::v1::TableEntry &entry);
  Status modify_entry(const pi::MatchKey &mk,
                      const ::p4::v1::TableEntry &entry);
  Status delete_entry(const pi::MatchKey &mk);

  void stream_message_response_register_cb(StreamMessageResponseCb cb,
                                           void *cookie);

  void handle_notification(common::p4_id_t table_id, pi::MatchKey match_key);

  IdleTimeoutBuffer(const IdleTimeoutBuffer &) = delete;
  IdleTimeoutBuffer &operator=(const IdleTimeoutBuffer &) = delete;
  IdleTimeoutBuffer(IdleTimeoutBuffer &&) = delete;
  IdleTimeoutBuffer &operator=(IdleTimeoutBuffer &&) = delete;

 private:
  class TaskSendNotifications;
  class TableInfoStore;

  device_id_t device_id;
  const pi_p4info_t *p4info{nullptr};
  std::unique_ptr<TableInfoStore> table_info_store;
  int64_t max_buffering_ns;
  std::unique_ptr<IdleTimeoutTaskQueue> task_queue;
  StreamMessageResponseCb cb{};
  void *cookie{nullptr};
  std::thread task_queue_thread;
  p4::v1::IdleTimeoutNotification notifications;
  std::atomic<size_t> drop_count{0};

  // start dropping notifications if queue grows too large
  static constexpr size_t max_queue_size = 1000;
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_IDLE_TIMEOUT_BUFFER_H_
