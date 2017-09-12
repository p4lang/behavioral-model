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

#include <bm/bm_sim/logger.h>

#include <grpc++/grpc++.h>

#include <p4/bm/dataplane_interface.grpc.pb.h>
#include <p4/p4runtime.grpc.pb.h>

#include <gtest/gtest.h>

#include <memory>
#include <set>
#include <string>

#include "base_test.h"
#include "switch_runner.h"

namespace sswitch_grpc {

namespace testing {

namespace {

constexpr char broadcast_json[] = TESTDATADIR "/broadcast.json";
constexpr char broadcast_proto[] = TESTDATADIR "/broadcast.proto.txt";

class SimpleSwitchGrpcTest_Broadcast : public SimpleSwitchGrpcBaseTest {
 protected:
  SimpleSwitchGrpcTest_Broadcast()
      : SimpleSwitchGrpcBaseTest(broadcast_proto),
        dataplane_channel(grpc::CreateChannel(
            dp_grpc_server_addr, grpc::InsecureChannelCredentials())),
        dataplane_stub(p4::bm::DataplaneInterface::NewStub(
            dataplane_channel)) { }

  void SetUp() override {
    SimpleSwitchGrpcBaseTest::SetUp();
    // this is not optimal, we really should avoid using the same switch
    // instance for all the tests
    SimpleSwitchGrpcRunnerTesting::create_broadcast_group(1);
    update_json(broadcast_json);
  }

  std::shared_ptr<grpc::Channel> dataplane_channel{nullptr};
  std::unique_ptr<p4::bm::DataplaneInterface::Stub> dataplane_stub{nullptr};
};

TEST_F(SimpleSwitchGrpcTest_Broadcast, SendAndReceive) {
  SimpleSwitchGrpcRunnerTesting::port_add(1);
  SimpleSwitchGrpcRunnerTesting::port_add(2);
  SimpleSwitchGrpcRunnerTesting::port_add(3);
  p4::bm::PacketStreamRequest request;
  request.set_device_id(device_id);
  request.set_port(1);
  request.set_packet(std::string(10, '\xab'));
  ClientContext context;
  auto stream = dataplane_stub->PacketStream(&context);
  auto check_recv = [&stream](const std::set<int> &ports) {
    p4::bm::PacketStreamResponse response;
    std::set<int> recv_ports;
    for (size_t i = 0; i < ports.size(); i++) {
      stream->Read(&response);
      recv_ports.insert(response.port());
    }
    EXPECT_EQ(recv_ports, ports);
  };
  stream->Write(request);
  check_recv({1, 2, 3});
  SimpleSwitchGrpcRunnerTesting::port_remove(2);
  stream->Write(request);
  check_recv({1, 3});
  stream->WritesDone();
  auto status = stream->Finish();
  EXPECT_TRUE(status.ok());
  SimpleSwitchGrpcRunnerTesting::port_remove(1);
  SimpleSwitchGrpcRunnerTesting::port_remove(3);
}

}  // namespace

}  // namespace testing

}  // namespace sswitch_grpc
