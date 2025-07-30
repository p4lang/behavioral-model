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

class ActionInfo{
public:
  int action_id;
  std::string action_name;
  std::vector<std::pair<int, unsigned char>> params; // pair of param id and value

  ActionInfo(int action_id, const std::string &action_name,
              const std::vector<std::pair<int, unsigned char>> &params)
        : action_id(action_id), action_name(action_name), params(params) {}
};

class SSGrpcFanoutTest_FanoutBase : public SimpleSwitchGrpcBaseTest {
 protected:
  using StreamType = grpc::ClientReaderWriter<p4::bm::PacketStreamRequest,
                                            p4::bm::PacketStreamResponse>;
  using GroupEntry = ::p4v1::MulticastGroupEntry;

  SSGrpcFanoutTest_FanoutBase(const char* proto, const char* json)
    : SimpleSwitchGrpcBaseTest(proto),
      p4json_file(json),
      dataplane_channel(grpc::CreateChannel(
          dp_grpc_server_addr, grpc::InsecureChannelCredentials())),
      dataplane_stub(p4::bm::DataplaneInterface::NewStub(
          dataplane_channel)) { }

  void SetUp() override {
    SimpleSwitchGrpcBaseTest::SetUp();
    update_json(p4json_file);
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
    std::multiset<OutputPkt> &received) {
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
    const uint32_t& count, std::multiset<OutputPkt> &received) {
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

  Status add_ap_table_entry(
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
    // Add actions as members of the selector's group
    for (const auto &act_info : actions) {
      auto *action_entry = act_set->add_action_profile_actions();
      auto *act = action_entry->mutable_action();
      act->set_action_id(act_info.action_id);

      for(auto param: act_info.params) {
        auto *param_entry = act->add_params();
        param_entry->set_param_id(param.first);
        param_entry->set_value(std::string(1, static_cast<char>(param.second)));
      }
      
      action_entry->set_weight(1);
    }
    return write(entity, p4v1::Update::INSERT);
  }

  Status add_table_entry(
      const int &table_id, const std::string & tbl_name, 
      const std::string &key_field_name,
      const std::string &key_value, const ActionInfo &action) {
    p4v1::Entity entity;
    auto *entry = entity.mutable_table_entry();
    entry->set_table_id(table_id);
    auto *mf = entry->add_match();
    mf->set_field_id(get_mf_id(p4info, tbl_name, key_field_name));
    mf->mutable_exact()->set_value(key_value);
    auto act = entry->mutable_action()->mutable_action();
    act->set_action_id(action.action_id);
    for (auto param : action.params) {
      auto *param_entry = act->add_params();
      param_entry->set_param_id(param.first);
      param_entry->set_value(std::string(1, static_cast<char>(param.second)));
    }
    return write(entity, p4v1::Update::INSERT);
  }

  Status create_mc_group(const GroupEntry &entry) {
    p4v1::WriteRequest request;
    request.set_device_id(device_id);
    auto *update = request.add_updates();
    update->set_type(p4v1::Update::INSERT);
    auto *entity = update->mutable_entity();
    auto *pre_entry = entity->mutable_packet_replication_engine_entry();
    auto *mc_entry = pre_entry->mutable_multicast_group_entry();
    mc_entry->CopyFrom(entry);
    p4v1::WriteResponse response;
    ClientContext context;
    return Write(&context, request, &response);
  }

  const char *p4json_file = nullptr;
  std::shared_ptr<grpc::Channel> dataplane_channel{nullptr};
  std::unique_ptr<p4::bm::DataplaneInterface::Stub> dataplane_stub{nullptr};
};

constexpr char ingress_single_selector_json[] = TESTDATADIR "/ingress_single_selector_test.json";
constexpr char ingress_single_selector_proto[] = TESTDATADIR "/ingress_single_selector_test.proto.txtpb";

class SSGrpcFanoutTest_SingleSelector : public SSGrpcFanoutTest_FanoutBase {
 protected:
  using StreamType = grpc::ClientReaderWriter<p4::bm::PacketStreamRequest,
                                            p4::bm::PacketStreamResponse>;

  SSGrpcFanoutTest_SingleSelector()
      : SSGrpcFanoutTest_FanoutBase(ingress_single_selector_proto, ingress_single_selector_json)
       { }

  void SetUp() override {
    SSGrpcFanoutTest_FanoutBase::SetUp();
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
  }

  const char *p4json_file = nullptr;
  std::shared_ptr<grpc::Channel> dataplane_channel{nullptr};
  std::unique_ptr<p4::bm::DataplaneInterface::Stub> dataplane_stub{nullptr};
  int table_id;
  int action_id_1;
  std::vector<int> action_1_param_ids;
  int action_id_2;
  std::vector<int> action_2_param_ids;
  int action_id_3;
  std::vector<int> action_3_param_ids;
};



TEST_F(SSGrpcFanoutTest_SingleSelector, SingleGroup) {

  std::vector<ActionInfo> actions = {
      {action_id_1, "foo1", {{action_1_param_ids[0], 1},
                               {action_1_param_ids[1], 1}}},
      {action_id_2, "foo2", {{action_2_param_ids[0], 2},
                               {action_2_param_ids[1], 2}}},
      {action_id_3, "foo3", {{action_3_param_ids[0], 3},
                               {action_3_param_ids[1], 3}}}
  };

  EXPECT_TRUE(add_ap_table_entry(table_id, "selector_tbl", "h.hdr.in_", "\xab", actions).ok());
  
  OutputPkt expected_1(1, "\xab\x00\x01\x00\x00");
  OutputPkt expected_2(2, "\xab\x00\x00\x02\x00");
  OutputPkt expected_3(3, "\xab\x00\x00\x00\x03");
  std::multiset<OutputPkt> expected_set = {expected_1, expected_2, expected_3};
  std::multiset<OutputPkt> received_set;

  EXPECT_TRUE(send_and_receive("\xab",1,3,received_set).ok());
  EXPECT_TRUE(received_set == expected_set);
}

TEST_F(SSGrpcFanoutTest_SingleSelector, TwoGroups) {

  std::vector<ActionInfo> actions_1 = {
      {action_id_1, "foo1", {{action_1_param_ids[0], 1},
                               {action_1_param_ids[1], 1}}},
      {action_id_2, "foo2", {{action_2_param_ids[0], 2},
                               {action_2_param_ids[1], 2}}},
      {action_id_3, "foo3", {{action_3_param_ids[0], 3},
                               {action_3_param_ids[1], 3}}}
  };

  std::vector<ActionInfo> actions_2 = {
      {action_id_1, "foo1", {{action_1_param_ids[0], 4},
                               {action_1_param_ids[1], 1}}},
      {action_id_2, "foo2", {{action_2_param_ids[0], 5},
                               {action_2_param_ids[1], 2}}},
      {action_id_2, "foo2", {{action_2_param_ids[0], 6},
                               {action_2_param_ids[1], 3}}}
  };
  EXPECT_TRUE(add_ap_table_entry(table_id, "selector_tbl", "h.hdr.in_", "\xab", actions_1).ok());
  EXPECT_TRUE(add_ap_table_entry(table_id, "selector_tbl", "h.hdr.in_", "\xaa", actions_2).ok());

  
  OutputPkt expected_1_1(1, "\xab\x00\x01\x00\x00");
  OutputPkt expected_1_2(2, "\xab\x00\x00\x02\x00");
  OutputPkt expected_1_3(3, "\xab\x00\x00\x00\x03");
  std::multiset<OutputPkt> expected_set_1 = {expected_1_1, expected_1_2, expected_1_3};
  std::multiset<OutputPkt> received_set_1;

  EXPECT_TRUE(send_and_receive("\xab",1,3,received_set_1).ok());
  EXPECT_TRUE(received_set_1 == expected_set_1);
  
  OutputPkt expected_2_1(1, "\xaa\x00\x04\x00\x00");
  OutputPkt expected_2_2(2, "\xaa\x00\x00\x05\x00");
  OutputPkt expected_2_3(3, "\xaa\x00\x00\x06\x00");
  std::multiset<OutputPkt> expected_set_2 = {expected_2_1, expected_2_2, expected_2_3};
  std::multiset<OutputPkt> received_set_2;

  EXPECT_TRUE(send_and_receive("\xaa",1,3,received_set_2).ok());
  EXPECT_TRUE(received_set_2 == expected_set_2);
}




constexpr char ingress_single_selector_mc_json[] = TESTDATADIR "/ingress_single_selector_mc_test.json";
constexpr char ingress_single_selector_mc_proto[] = TESTDATADIR "/ingress_single_selector_mc_test.proto.txtpb";

class SSGrpcFanoutTest_SingleSelector_Multicast : public SSGrpcFanoutTest_FanoutBase{
protected:  
  SSGrpcFanoutTest_SingleSelector_Multicast()
      : SSGrpcFanoutTest_FanoutBase(ingress_single_selector_mc_proto, ingress_single_selector_mc_json) { }

  void SetUp() override {
    SSGrpcFanoutTest_FanoutBase::SetUp();
    selector_table_id = get_table_id(p4info, "selector_tbl");
    selector_action_id_1 = get_action_id(p4info, "foo1");
    selector_action_1_param_ids.push_back(get_param_id(p4info, "foo1", "val"));
    selector_action_1_param_ids.push_back(get_param_id(p4info, "foo1", "port"));

    selector_action_id_2 = get_action_id(p4info, "foo2");
    selector_action_2_param_ids.push_back(get_param_id(p4info, "foo2", "val"));
    selector_action_2_param_ids.push_back(get_param_id(p4info, "foo2", "port"));

    mc_table_id = get_table_id(p4info, "multicast_tbl");
    mc_multicast_action_id = get_action_id(p4info, "multicast");
    mc_multicast_action_param_ids.push_back(get_param_id(p4info, "multicast", "mc_grp"));
    mc_forward_action_id_2 = get_action_id(p4info, "forward");
    mc_forward_action_param_ids_2.push_back(get_param_id(p4info, "forward", "port"));
  }

  int selector_table_id;
  int selector_action_id_1;
  std::vector<int> selector_action_1_param_ids;
  int selector_action_id_2;
  std::vector<int> selector_action_2_param_ids;

  int mc_table_id;
  int mc_multicast_action_id;
  std::vector<int> mc_multicast_action_param_ids;
  int mc_forward_action_id_2;
  std::vector<int> mc_forward_action_param_ids_2;


};


TEST_F(SSGrpcFanoutTest_SingleSelector_Multicast, SingleMCGroup) {
  int16_t group_id = 1;
  GroupEntry group;
  group.set_multicast_group_id(group_id);
  // Set group members for group 1
  std::vector<uint32_t> group_replicas = {1, 2, 3}; 
  for (const auto &r : group_replicas) {
    auto *replica = group.add_replicas();
    replica->set_instance(r);
    replica->set_egress_port(r);
  }
  EXPECT_TRUE(create_mc_group(group).ok());

  std::vector<ActionInfo> selector_actions = {
    {selector_action_id_1, "foo1", {{selector_action_1_param_ids[0], 1},
      {selector_action_1_param_ids[1], 1}}},
    {selector_action_id_2, "foo2", {{selector_action_2_param_ids[0], 2},
      {selector_action_2_param_ids[1], 2}}}};
  EXPECT_TRUE(add_ap_table_entry(selector_table_id, "selector_tbl", "h.hdr.in_", "\xab", selector_actions).ok());

  ActionInfo multicast_action(mc_multicast_action_id, "multicast",
      {{mc_multicast_action_param_ids[0], group_id}});
  EXPECT_TRUE(add_table_entry(mc_table_id, "multicast_tbl", "h.hdr.f1", "\xac", multicast_action).ok());

  OutputPkt expected_1(1, "\xab\x00\x01\x00\x00");
  OutputPkt expected_2(2, "\xab\x00\x01\x00\x00");
  OutputPkt expected_3(3, "\xab\x00\x01\x00\x00");
  OutputPkt expected_4(1, "\xab\x00\x00\x02\x00");
  OutputPkt expected_5(2, "\xab\x00\x00\x02\x00");
  OutputPkt expected_6(3, "\xab\x00\x00\x02\x00");
  std::multiset<OutputPkt> expected_set = {expected_1, expected_2, expected_3, expected_4, expected_5, expected_6};
  std::multiset<OutputPkt> received_set;

  EXPECT_TRUE(send_and_receive("\xab",1,6,received_set).ok());
  EXPECT_TRUE(received_set == expected_set);
}



constexpr char ingress_two_selectors_json[] = TESTDATADIR "/ingress_two_selectors_test.json";
constexpr char ingress_two_selectors_proto[] = TESTDATADIR "/ingress_two_selectors_test.proto.txtpb";

class SSGrpcFanoutTest_TwoSelectors : public SSGrpcFanoutTest_FanoutBase {
 protected:
  using StreamType = grpc::ClientReaderWriter<p4::bm::PacketStreamRequest,
                                            p4::bm::PacketStreamResponse>;

  SSGrpcFanoutTest_TwoSelectors()
      : SSGrpcFanoutTest_FanoutBase(ingress_two_selectors_proto, ingress_two_selectors_json)
       { }

  void SetUp() override {
    SSGrpcFanoutTest_FanoutBase::SetUp();
    selector_table_id_1 = get_table_id(p4info, "selector_tbl_1");
    selector_table_id_2 = get_table_id(p4info, "selector_tbl_2");
    action_id_1 = get_action_id(p4info, "foo1");
    action_1_param_ids.push_back(get_param_id(p4info, "foo1", "val"));
    action_1_param_ids.push_back(get_param_id(p4info, "foo1", "port"));

    action_id_2 = get_action_id(p4info, "foo2");
    action_2_param_ids.push_back(get_param_id(p4info, "foo2", "val"));
    action_2_param_ids.push_back(get_param_id(p4info, "foo2", "port"));

    action_id_3 = get_action_id(p4info, "foo3");
    action_3_param_ids.push_back(get_param_id(p4info, "foo3", "val"));
    action_3_param_ids.push_back(get_param_id(p4info, "foo3", "port"));
  }

  const char *p4json_file = nullptr;
  std::shared_ptr<grpc::Channel> dataplane_channel{nullptr};
  std::unique_ptr<p4::bm::DataplaneInterface::Stub> dataplane_stub{nullptr};
  int selector_table_id_1;
  int selector_table_id_2;
  int action_id_1;
  std::vector<int> action_1_param_ids;
  int action_id_2;
  std::vector<int> action_2_param_ids;
  int action_id_3;
  std::vector<int> action_3_param_ids;
};

TEST_F(SSGrpcFanoutTest_TwoSelectors, SingleGroup) {

  std::vector<ActionInfo> actions_1 = {
      {action_id_1, "foo1", {{action_1_param_ids[0], 1},
                               {action_1_param_ids[1], 1}}},
      {action_id_2, "foo2", {{action_2_param_ids[0], 2},
                               {action_2_param_ids[1], 2}}},
      {action_id_3, "foo3", {{action_3_param_ids[0], 3},
                               {action_3_param_ids[1], 3}}}
  };

  std::vector<ActionInfo> actions_2 = {
      {action_id_1, "foo1", {{action_1_param_ids[0], 4},
                               {action_1_param_ids[1], 2}}},
      {action_id_2, "foo2", {{action_2_param_ids[0], 5},
                               {action_2_param_ids[1], 3}}}
  };

  EXPECT_TRUE(add_ap_table_entry(selector_table_id_1, "selector_tbl_1", "h.hdr.in_", "\xab", actions_1).ok());
  EXPECT_TRUE(add_ap_table_entry(selector_table_id_2, "selector_tbl_2", "h.hdr.in_", "\xab", actions_2).ok());

  OutputPkt expected_1(2, "\xab\x00\x04\x00\x00");
  OutputPkt expected_2(3, "\xab\x00\x01\x05\x00");

  OutputPkt expected_3(2, "\xab\x00\x04\x02\x00");
  OutputPkt expected_4(3, "\xab\x00\x00\x05\x00");

  OutputPkt expected_5(2, "\xab\x00\x04\x00\x03");
  OutputPkt expected_6(3, "\xab\x00\x00\x05\x03");

  std::multiset<OutputPkt> expected_set = {expected_1, expected_2, expected_3, expected_4, expected_5, expected_6};
  std::multiset<OutputPkt> received_set;

  EXPECT_TRUE(send_and_receive("\xab",1,6,received_set).ok());
  EXPECT_TRUE(received_set == expected_set);
}


constexpr char egress_single_selector_json[] = TESTDATADIR "/egress_single_selector_test.json";
constexpr char egress_single_selector_proto[] = TESTDATADIR "/egress_single_selector_test.proto.txtpb";

class SSGrpcFanoutTest_EgressSingleSelector : public SSGrpcFanoutTest_FanoutBase {
 protected:
  using StreamType = grpc::ClientReaderWriter<p4::bm::PacketStreamRequest,
                                            p4::bm::PacketStreamResponse>;

  SSGrpcFanoutTest_EgressSingleSelector()
      : SSGrpcFanoutTest_FanoutBase(egress_single_selector_proto, egress_single_selector_json)
       { }

  void SetUp() override {
    SSGrpcFanoutTest_FanoutBase::SetUp();
    table_id = get_table_id(p4info, "selector_tbl");
    action_id_1 = get_action_id(p4info, "foo1");
    action_1_param_ids.push_back(get_param_id(p4info, "foo1", "val"));

    action_id_2 = get_action_id(p4info, "foo2");
    action_2_param_ids.push_back(get_param_id(p4info, "foo2", "val"));

    action_id_3 = get_action_id(p4info, "foo3");
    action_3_param_ids.push_back(get_param_id(p4info, "foo3", "val"));
  }

  const char *p4json_file = nullptr;
  std::shared_ptr<grpc::Channel> dataplane_channel{nullptr};
  std::unique_ptr<p4::bm::DataplaneInterface::Stub> dataplane_stub{nullptr};
  int table_id;
  int action_id_1;
  std::vector<int> action_1_param_ids;
  int action_id_2;
  std::vector<int> action_2_param_ids;
  int action_id_3;
  std::vector<int> action_3_param_ids;
};



TEST_F(SSGrpcFanoutTest_EgressSingleSelector, SingleGroup) {
  int16_t group_id = 2;
  GroupEntry group;
  group.set_multicast_group_id(group_id);
  // Set group members for group 2
  std::vector<uint32_t> group_replicas = {1,2}; 
  for (const auto &r : group_replicas) {
    auto *replica = group.add_replicas();
    replica->set_instance(r);
    replica->set_egress_port(r);
  }
  EXPECT_TRUE(create_mc_group(group).ok());

  std::vector<ActionInfo> actions = {
      {action_id_1, "foo1", {{action_1_param_ids[0], 1}}},
      {action_id_2, "foo2", {{action_2_param_ids[0], 2}}},
      {action_id_3, "foo3", {{action_3_param_ids[0], 3}}}
  };

  EXPECT_TRUE(add_ap_table_entry(table_id, "selector_tbl", "h.hdr.in_", "\xab", actions).ok());
  
  OutputPkt expected_1(1, "\xab\x00\x01\x00\x00");
  OutputPkt expected_2(1, "\xab\x00\x00\x02\x00");
  OutputPkt expected_3(1, "\xab\x00\x00\x00\x03");
  OutputPkt expected_4(2, "\xab\x00\x01\x00\x00");
  OutputPkt expected_5(2, "\xab\x00\x00\x02\x00");
  OutputPkt expected_6(2, "\xab\x00\x00\x00\x03");
  std::multiset<OutputPkt> expected_set = {expected_1, expected_2, expected_3, expected_4, expected_5, expected_6};
  std::multiset<OutputPkt> received_set;

  EXPECT_TRUE(send_and_receive("\xab",1,6,received_set).ok());
  EXPECT_TRUE(received_set == expected_set);
}


}  // namespace

}  // namespace testing

}  // namespace sswitch_grpc
