/* Copyright 2025 Contributors to the P4 Project
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

#include <grpcpp/grpcpp.h>

#include <p4/bm/dataplane_interface.grpc.pb.h>
#include <p4/v1/p4runtime.grpc.pb.h>

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <thread>
#include <vector>
#include <set>

#include "base_test.h"
#include "utils.h"

namespace p4v1 = ::p4::v1;

namespace sswitch_grpc {

namespace testing {

namespace {

constexpr char ingress_round_robin_json[] = TESTDATADIR "/ingress_round_robin_test.json";
constexpr char ingress_round_robin_proto[] = TESTDATADIR "/ingress_round_robin_test.proto.txtpb";

std::string port_to_bytes(int port) {
  std::string v;
  v.push_back(static_cast<char>((port >> 8) & 0xff));
  v.push_back(static_cast<char>(port & 0xff));
  return v;
}

class OutputPkt{
public:
  uint32_t eg_port;
  unsigned char in_;
  unsigned char hash_val;
  unsigned char f1;
  unsigned char f2;
  unsigned char f3;
  OutputPkt(uint32_t eg_port, const char* header)
      : eg_port(eg_port), in_(header[0]), hash_val(header[1]),
        f1(header[2]), f2(header[3]), f3(header[4]) {}

  bool operator<(const OutputPkt& other) const {
    return std::tie(eg_port, in_, hash_val, f1, f2, f3) <
           std::tie(other.eg_port, other.in_, other.hash_val,
                    other.f1, other.f2, other.f3);
  }
  bool operator==(const OutputPkt& other) const {
    return std::tie(eg_port, in_, hash_val, f1, f2, f3) ==
           std::tie(other.eg_port, other.in_, other.hash_val,
                    other.f1, other.f2, other.f3);
  }
};

class SimpleSwitchGrpcTest_RoundRobin : public SimpleSwitchGrpcBaseTest {
 protected:
  using StreamType = grpc::ClientReaderWriter<p4::bm::PacketStreamRequest,
                                            p4::bm::PacketStreamResponse>;
  // action id, action name, param id 1, param 1, param id 2, param 2                                         
  using ActionInfo = std::tuple<int, std::string, int, unsigned char, int, unsigned char>;
  SimpleSwitchGrpcTest_RoundRobin()
      : SimpleSwitchGrpcBaseTest(ingress_round_robin_proto),
        dataplane_channel(grpc::CreateChannel(
            dp_grpc_server_addr, grpc::InsecureChannelCredentials())),
        dataplane_stub(p4::bm::DataplaneInterface::NewStub(
            dataplane_channel)) { }

  void SetUp() override {
    SimpleSwitchGrpcBaseTest::SetUp();
    update_json(ingress_round_robin_json);
    table_id = get_table_id(p4info, "selector_tbl");
    action_id_1 = get_action_id(p4info, "foo1");
    action_1_param_ids.push_back(get_param_id(p4info, "foo1", "val"));
    action_1_param_ids.push_back(get_param_id(p4info, "foo1", "port"));

    action_id_2 = get_action_id(p4info, "foo2");
    action_2_param_ids.push_back(get_param_id(p4info, "foo2", "val"));
    action_2_param_ids.push_back(get_param_id(p4info, "foo2", "port"));

    action_id_3 = get_action_id(p4info, "foo3");
    action_3_param_ids.push_back(get_param_id(p4info, "foo3", "val"));
    action_3_param_ids.push_back(get_param_id(p4info, "foo3", "port"));

    act_prof_id = get_act_prof_id(p4info, "rr_selector");
  }

  void send_packet(StreamType* stream, const char& in_, const int& ig_port) {
    // The testing header is 
    // header hdr_t {
    //   bit<8> in_;
    //   bit<8> hash_val;
    //   bit<8> f1;
    //   bit<8> f2;
    //   bit<8> f3;
    // }
    std::string pkt(5, '\0');
    pkt[0] = in_;
    p4::bm::PacketStreamRequest request;
    request.set_device_id(device_id);
    request.set_port(ig_port);
    request.set_packet(pkt);
    stream->Write(request);
  }

  bool receive_packets(StreamReceiver<StreamType, 
    p4::bm::PacketStreamResponse> &stream_receiver, const uint32_t& count, 
    std::set<OutputPkt> &received) {
    const std::chrono::milliseconds timeout(500);
    for (size_t i = 0; i < count; i++) {
      auto msg = stream_receiver.get(
          [](const p4::bm::PacketStreamResponse &) { return true; }, timeout);
      if (msg == nullptr) return false;
      auto port = msg->port();
      if (msg->packet().size() < 5) {
        return false;
      }
      char header[5];
      memcpy(header, msg->packet().data(), 5);
      received.emplace(port, header);
    }
    return true;
  }

  // use the receive in pre
  grpc::Status send_and_receive(const char* in_, const int& ig_port, 
    const uint32_t& count, std::set<OutputPkt> &received) {
    ClientContext context;
    auto dp_stream = dataplane_stub->PacketStream(&context);
    StreamReceiver<StreamType, p4::bm::PacketStreamResponse> 
            stream_receiver(dp_stream.get());
    send_packet(dp_stream.get(), in_[0], ig_port);
    
    auto close_stream = [&dp_stream]() {
      dp_stream->WritesDone();
      dp_stream->Finish();
    };

    if (!receive_packets(stream_receiver, count, received)) {
      close_stream();
      return grpc::Status(grpc::StatusCode::UNKNOWN, "Failed to receive packets");
    }
    close_stream();
    return grpc::Status::OK;
  }

  Status add_table_entry(
      const int &table_id, const std::string & tbl_name, 
      const std::string &key_field_name,
      const std::string &key_value, const std::vector<ActionInfo> &actions) {
    p4v1::Entity entity;
    auto *entry = entity.mutable_table_entry();
    entry->set_table_id(table_id);
    auto *mf = entry->add_match();
    mf->set_field_id(get_mf_id(p4info, tbl_name, key_field_name));
    mf->mutable_exact()->set_value(key_value);
    auto act_set = entry->mutable_action()->mutable_action_profile_action_set();
    for (const auto &act_info : actions) {
      auto *action_entry = act_set->add_action_profile_actions();
      auto *act = action_entry->mutable_action();
      act->set_action_id(std::get<0>(act_info));

      auto *param1 = act->add_params();
      param1->set_param_id(std::get<2>(act_info));
      param1->set_value(std::string(1, std::get<3>(act_info)));

      auto *param2 = act->add_params();
      param2->set_param_id(std::get<4>(act_info));
      param2->set_value(std::string(1, std::get<5>(act_info)));
      
      action_entry->set_weight(1);
    }


    return write(entity, p4v1::Update::INSERT);
  }

  std::shared_ptr<grpc::Channel> dataplane_channel{nullptr};
  std::unique_ptr<p4::bm::DataplaneInterface::Stub> dataplane_stub{nullptr};
  int act_prof_id;
  int table_id;
  int action_id_1;
  std::vector<int> action_1_param_ids;
  int action_id_2;
  std::vector<int> action_2_param_ids;
  int action_id_3;
  std::vector<int> action_3_param_ids;
};



TEST_F(SimpleSwitchGrpcTest_RoundRobin, SingleGroup) {

  std::vector<ActionInfo> actions = {
      {action_id_1, "foo1", action_1_param_ids[0], 1,
       action_1_param_ids[1], 1},
      {action_id_2, "foo2", action_2_param_ids[0], 2,
       action_2_param_ids[1], 2},
      {action_id_3, "foo3", action_3_param_ids[0], 3,
       action_3_param_ids[1], 3}};
  
  EXPECT_TRUE(add_table_entry(table_id, "selector_tbl", "h.hdr.in_", "\xab", actions).ok());
  
  OutputPkt expected_1(1, "\xab\x00\x01\x00\x00");
  OutputPkt expected_2(2, "\xab\x00\x00\x02\x00");
  OutputPkt expected_3(3, "\xab\x00\x00\x00\x03");
  std::set<OutputPkt> expected_set = {expected_1, expected_2, expected_3};
  std::set<OutputPkt> received_set;

  EXPECT_TRUE(send_and_receive("\xab",1,3,received_set).ok());
  EXPECT_TRUE(received_set == expected_set);
}

}  // namespace

}  // namespace testing

}  // namespace sswitch_grpc
