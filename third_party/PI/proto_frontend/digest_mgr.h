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

#ifndef SRC_DIGEST_MGR_H_
#define SRC_DIGEST_MGR_H_

#include <PI/frontends/proto/device_mgr.h>
#include <PI/pi_learn.h>

#include <chrono>
#include <memory>
#include <thread>

#include "google/rpc/status.pb.h"
#include "p4/config/v1/p4info.pb.h"
#include "p4/v1/p4runtime.pb.h"

#include "common.h"

namespace pi {

namespace fe {

namespace proto {

namespace common {
class SessionTemp;
}  // namespace common

template <typename Clock> class TaskQueue;
using DigestTaskQueue = TaskQueue<std::chrono::steady_clock>;

class DigestMgr {
 public:
  using device_id_t = DeviceMgr::device_id_t;
  using p4_id_t = common::p4_id_t;
  using StreamMessageResponseCb = DeviceMgr::StreamMessageResponseCb;
  using Status = DeviceMgr::Status;

  explicit DigestMgr(device_id_t device_id);
  ~DigestMgr();

  Status p4_change(const p4::config::v1::P4Info &p4info);

  Status config_write(const p4::v1::DigestEntry &entry,
                      p4::v1::Update::Type type,
                      const common::SessionTemp &session);

  Status config_read(const p4::v1::DigestEntry &entry,
                     p4::v1::ReadResponse *response) const;

  void ack(const p4::v1::DigestListAck &ack);

  void stream_message_response_register_cb(StreamMessageResponseCb cb,
                                           void *cookie);

  void stream_message_response_unregister_cb();

  DigestMgr(const DigestMgr &) = delete;
  DigestMgr &operator=(const DigestMgr &) = delete;
  DigestMgr(DigestMgr &&) = delete;
  DigestMgr &operator=(DigestMgr &&) = delete;

 private:
  static void digest_cb(pi_learn_msg_t *msg, void *cookie);

  class State;
  class SweepTasks;

  device_id_t device_id;
  std::unique_ptr<DigestTaskQueue> task_queue;
  std::unique_ptr<State> state;
  std::unique_ptr<SweepTasks> sweep_tasks;
  StreamMessageResponseCb cb;
  void *cookie;
  std::thread task_queue_thread;
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_DIGEST_MGR_H_
