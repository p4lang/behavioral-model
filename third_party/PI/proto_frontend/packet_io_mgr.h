/* Copyright 2013-present Barefoot Networks, Inc.
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

#ifndef SRC_PACKET_IO_MGR_H_
#define SRC_PACKET_IO_MGR_H_

#include <PI/frontends/proto/device_mgr.h>
#include <PI/pi.h>

#include <memory>
#include <mutex>

#include "google/rpc/status.pb.h"
#include "p4/config/v1/p4info.pb.h"
#include "p4/server/v1/config.pb.h"
#include "p4/v1/p4runtime.pb.h"

#include "server_config/server_config.h"

namespace pi {

namespace fe {

namespace proto {

class PacketInMutate;
class PacketOutMutate;

class PacketIOMgr {
 public:
  using device_id_t = DeviceMgr::device_id_t;
  using StreamMessageResponseCb = DeviceMgr::StreamMessageResponseCb;
  using Status = DeviceMgr::Status;

  PacketIOMgr(device_id_t device_id, ServerConfigAccessor *server_config);
  ~PacketIOMgr();

  void p4_change(const p4::config::v1::P4Info &p4info);

  Status packet_out_send(const p4::v1::PacketOut &packet) const;
  // If stream error reporting is disabled, of in the absence of error, we set
  // canonical_code to OK in the StreamError message.
  Status packet_out_send(const p4::v1::PacketOut &packet,
                         p4::v1::StreamError *stream_error) const;

  void packet_in_register_cb(StreamMessageResponseCb cb, void *cookie);

  PacketIOMgr(const PacketIOMgr &) = delete;
  PacketIOMgr &operator=(const PacketIOMgr &) = delete;
  PacketIOMgr(PacketIOMgr &&) = delete;
  PacketIOMgr &operator=(PacketIOMgr &&) = delete;

 private:
  static void packet_in_cb(pi_dev_id_t dev_id, const char *pkt, size_t size,
                           void *cookie);

  p4::server::v1::StreamConfig::ErrorReportingLevel error_reporting() const;

  using Mutex = std::mutex;
  using Lock = std::lock_guard<Mutex>;
  device_id_t device_id;
  ServerConfigAccessor *server_config;
  mutable Mutex mutex{};
  std::unique_ptr<PacketInMutate> packet_in_mutate;
  std::unique_ptr<PacketOutMutate> packet_out_mutate;

  StreamMessageResponseCb cb_;
  void *cookie_;
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_PACKET_IO_MGR_H_
