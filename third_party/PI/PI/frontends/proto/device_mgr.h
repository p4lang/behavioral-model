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

#ifndef PI_FRONTENDS_PROTO_DEVICE_MGR_H_
#define PI_FRONTENDS_PROTO_DEVICE_MGR_H_

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "google/rpc/status.pb.h"
#include "p4/config/v1/p4info.pb.h"
#include "p4/server/v1/config.pb.h"
#include "p4/v1/p4runtime.pb.h"

#if __has_cpp_attribute(deprecated)
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++14-extensions"
#endif  // clang
#define _PI_DEPRECATED [[deprecated]]  // NOLINT(whitespace/braces)
#else
#define _PI_DEPRECATED
#endif  // deprecated

namespace pi {

namespace fe {

namespace proto {

// forward declaration for PIMPL class
class DeviceMgrImp;

// the gRPC server will instantiate one DeviceMgr object per device
class DeviceMgr {
 public:
  using device_id_t = uint64_t;
  using Status = ::google::rpc::Status;
  using StreamMessageResponseCb = std::function<void(
      device_id_t, p4::v1::StreamMessageResponse *msg, void *cookie)>;

  explicit DeviceMgr(device_id_t device_id);

  ~DeviceMgr();

  // New pipeline_config_set and pipeline_config_get methods to replace init,
  // update_start and update_end
  Status pipeline_config_set(
      p4::v1::SetForwardingPipelineConfigRequest::Action action,
      const p4::v1::ForwardingPipelineConfig &config);

  Status pipeline_config_get(
      p4::v1::GetForwardingPipelineConfigRequest::ResponseType response_type,
      p4::v1::ForwardingPipelineConfig *config);

  Status write(const p4::v1::WriteRequest &request);

  Status read(const p4::v1::ReadRequest &request,
              p4::v1::ReadResponse *response) const;
  Status read_one(const p4::v1::Entity &entity,
                  p4::v1::ReadResponse *response) const;

  Status stream_message_request_handle(
      const p4::v1::StreamMessageRequest &request);

  void stream_message_response_register_cb(StreamMessageResponseCb cb,
                                           void *cookie);

  Status server_config_set(const p4::server::v1::Config &config);

  Status server_config_get(p4::server::v1::Config *config);

  _PI_DEPRECATED
  static void init(size_t max_devices);

  static Status init();

  static Status init(const p4::server::v1::Config &config);

  static Status init(const std::string &config_text,
                     const std::string &version = "v1");

  static void destroy();

 private:
  // PIMPL design
  std::unique_ptr<DeviceMgrImp> pimp;
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#if __has_cpp_attribute(deprecated)
#if defined(__clang__)
#pragma clang diagnostic pop
#endif  // clang
#endif  // deprecated

#undef _PI_DEPRECATED

#endif  // PI_FRONTENDS_PROTO_DEVICE_MGR_H_
