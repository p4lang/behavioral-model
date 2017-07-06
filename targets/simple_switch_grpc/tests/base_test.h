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

#ifndef SIMPLE_SWITCH_GRPC_TESTS_BASE_TEST_H_
#define SIMPLE_SWITCH_GRPC_TESTS_BASE_TEST_H_

#include <p4/config/p4info.grpc.pb.h>
#include <p4/p4runtime.grpc.pb.h>

#include <gtest/gtest.h>

#include <memory>

#include "utils.h"

namespace grpc {

class Channel;

}  // namespace grpc

namespace sswitch_grpc {

namespace testing {

using grpc::ClientContext;
using grpc::Status;

class SimpleSwitchGrpcBaseTest : public ::testing::Test {
 public:
  static constexpr char grpc_server_addr[] = "0.0.0.0:50056";
  static constexpr char dp_grpc_server_addr[] = "0.0.0.0:50057";
  static constexpr int cpu_port = 64;
  static constexpr int device_id = 3;

 protected:
  explicit SimpleSwitchGrpcBaseTest(const char *p4info_proto_txt_path);

  void update_json(const char *json_path);

  std::shared_ptr<grpc::Channel> p4runtime_channel;
  std::unique_ptr<p4::P4Runtime::Stub> p4runtime_stub;
  p4::config::P4Info p4info{};
};

}  // namespace testing

}  // namespace sswitch_grpc

#endif  // SIMPLE_SWITCH_GRPC_TESTS_BASE_TEST_H_
