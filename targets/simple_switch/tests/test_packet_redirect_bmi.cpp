/* * Copyright 2025.
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
 * Francois-R.Boyer@PolyMtl.ca
 * Based on code of "test_packet_redirect.cpp"
 * By Antonin Bas
 *
 */

#include <gtest/gtest.h>

#include <bm/config.h>
#include <bm/bm_apps/packet_pipe.h>
#include <bm/bm_sim/logger.h>

#include <initializer_list>
#include <set>
#include <string>
#include <memory>
#include <vector>
#include <array>
#include <cassert>
#include <cstdlib>

#include <boost/filesystem.hpp>

#include "simple_switch.h"

#include "utils.h"
#include "pcap_mock/pcap_mock.hpp"

namespace fs = boost::filesystem;

using bm::MatchErrorCode;
using bm::ActionData;
using bm::MatchKeyParam;
using bm::entry_handle_t;


namespace {

class Ports {
public:
  static std::string generate_name_from_number(int port_number) {
    return "i" + std::to_string(port_number); 
  }
  static int get_number_from_name(const std::string port_name) {
    assert(port_name[0] == 'i');
    return atoi(&port_name[1]);
  }
  //NOTE: Port numbers are 0-based, so number can be directly used as an index.
  static void add_args_for_n_ports(std::vector<std::string>& args_to_modify,
                                   int n_ports) {
    for (int i = 0; i < n_ports; ++i) {
      args_to_modify.push_back("-i");
      args_to_modify.push_back(
                            std::to_string(i)+"@"+generate_name_from_number(i));
    }
  }
  void update_ports(int n_ports) {
    ports_.clear();
    for (int i = 0; i < n_ports; ++i)
      ports_.push_back(
                      pcap_mock::get_pcap_object(generate_name_from_number(i)));
  }
  pcap* get_port_from_number(int port_number) {
    return ports_.at(port_number); 
  }
  int get_number_from_port(pcap* port) {
    return get_number_from_name(pcap_mock::get_name(port));
  }

  void send(int port, const char* data, size_t data_size) {
    pcap_mock::simulate_packets_received(get_port_from_number(port), 
                                         std::vector<std::vector<u_char>>{
                                           std::vector<u_char>(data, 
                                                               data+data_size)
                                         });
  }
  void read(char* buffer, size_t length, int* received_port_out) {
    pcap_mock::Packet p = pcap_mock::get_sent_packet();
    memcpy(buffer, p.data.data(), std::min(p.data.size(), length));
    *received_port_out = get_number_from_port(p.pcap_object);
  }
  void start() {
    for (auto&& p : ports_)
      if (p) pcap_mock::clear(p);
  }
  
private:
  std::vector<pcap*> ports_;
};


}  // namespace

class SimpleSwitch_PacketRedirectP4_BMI : public ::testing::Test {
 protected:
  static constexpr size_t kMaxBufSize = 512;

  static constexpr bm::device_id_t device_id{0};

  SimpleSwitch_PacketRedirectP4_BMI()
      : //packet_inject(packet_in_addr),
        // packet_inject(interfaces),
        events(event_logger_addr) { }

  // Per-test-case set-up.
  // We make the switch a shared resource for all tests. This is mainly because
  // the simple_switch target detaches threads
  static void SetUpTestCase() {
    // bm::Logger::set_logger_console();
#ifdef BM_ELOG_ON
    auto event_transport = bm::TransportIface::make_nanomsg(event_logger_addr);
    event_transport->open();
    bm::EventLogger::init(std::move(event_transport));
#endif

    test_switch = new SimpleSwitch(8);  // 8 ports

    // load JSON
    fs::path json_path = fs::path(testdata_dir) / fs::path(test_json);
    test_switch->init_objects(json_path.string());

    std::vector<std::string> args = { "test_packet_redirect_bmi", "--no-p4" };
    static constexpr int n_interfaces = 5;
    Ports::add_args_for_n_ports(args, n_interfaces);
    std::vector<char*> argv; for (auto&& a : args) argv.push_back(a.data());
    test_switch->init_from_command_line_options(argv.size(), argv.data(), 
                                                nullptr, nullptr);
    packet_inject.update_ports(n_interfaces);

    test_switch->start_and_return();
  }

  // Per-test-case tear-down.
  static void TearDownTestCase() {
    delete test_switch;
    bm::EventLogger::init(nullptr);  // close nanomsg socket
  }

  void SetUp() override {
    packet_inject.start();

    events.start();

    // default actions for all tables
    test_switch->mt_set_default_action(0, "t_ingress_1", "_nop", ActionData());
    test_switch->mt_set_default_action(0, "t_ingress_2", "_nop", ActionData());
    test_switch->mt_set_default_action(0, "t_egress", "_nop", ActionData());
    test_switch->mt_set_default_action(0, "t_exit", "set_hdr", ActionData());
  }

  void TearDown() override {
    // kind of experimental, so reserved for testing
    test_switch->reset_state();
  }

  bool check_event_table_hit(const NNEventListener::NNEvent &event,
                             const std::string &name) {
    return (event.type == NNEventListener::TABLE_HIT) &&
        (event.id == test_switch->get_table_id(name));
  }

  bool check_event_table_miss(const NNEventListener::NNEvent &event,
                              const std::string &name) {
    return (event.type == NNEventListener::TABLE_MISS) &&
        (event.id == test_switch->get_table_id(name));
  }

  bool check_event_action_execute(const NNEventListener::NNEvent &event,
                                  const std::string &t_name,
                                  const std::string &a_name) {
    return (event.type == NNEventListener::ACTION_EXECUTE) &&
        (event.id == test_switch->get_action_id(t_name, a_name));
  }

  static std::string pid(packet_id_t copy_id) {
    return std::to_string(SimpleSwitch::get_packet_id()) + "." +
        std::to_string(copy_id);
  }

 protected:
  static const char event_logger_addr[];
  static const char packet_in_addr[];
  static SimpleSwitch *test_switch;
  // static Ports ports;
  // bm_apps::PacketInject packet_inject;
  static Ports packet_inject;
  // PacketInReceiver receiver{};
  static constexpr Ports& receiver = packet_inject;
  NNEventListener events;

 private:
  static const char testdata_dir[];
  static const char test_json[];
};

// In theory, I could be using an 'inproc' transport here. However, I observe a
// high number of packet drops when switching to 'inproc', which is obviosuly
// causing the tests to fail. PUB/SUB is not a reliable protocol and therefore
// packet drops are to be expected when the phblisher is faster than the
// consummer. However, I do not believe my consummer is that slow and I never
// observe the drops with 'ipc'
const char SimpleSwitch_PacketRedirectP4_BMI::event_logger_addr[] =
    "ipc:///tmp/test_events_abc123";
const char SimpleSwitch_PacketRedirectP4_BMI::packet_in_addr[] =
    "ipc:///tmp/test_packet_in_abc123";

SimpleSwitch *SimpleSwitch_PacketRedirectP4_BMI::test_switch = nullptr;
Ports SimpleSwitch_PacketRedirectP4_BMI::packet_inject;

const char SimpleSwitch_PacketRedirectP4_BMI::testdata_dir[] = TESTDATADIR;
const char SimpleSwitch_PacketRedirectP4_BMI::test_json[] =
    "packet_redirect.json";

TEST_F(SimpleSwitch_PacketRedirectP4_BMI, Baseline) {
  static constexpr int port_in = 1;
  static constexpr int port_out = 2;

  std::vector<MatchKeyParam> match_key;
  match_key.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x01"));
  match_key.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x00", 1));
  ActionData data;
  data.push_back_action_data(port_out);
  entry_handle_t handle;
  MatchErrorCode rc = test_switch->mt_add_entry(0, "t_ingress_1", match_key,
                                                "_set_port", std::move(data),
                                                &handle);
  ASSERT_EQ(MatchErrorCode::SUCCESS, rc);
  const char pkt[] = {'\x01', '\x00', '\x00', '\x00'};
  packet_inject.send(port_in, pkt, sizeof(pkt));

  // int recv_port = port_out;
  char recv_buffer[kMaxBufSize];
  int recv_port = -1;
  receiver.read(recv_buffer, sizeof(pkt), &recv_port);
  // make sure that standard_metadata.packet_length was updated after removing
  // header
  ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  ASSERT_EQ(port_out, recv_port);

#ifdef BM_ELOG_ON
  // event check
  std::vector<NNEventListener::NNEvent> pevents;
  events.get_and_remove_events(pid(0), &pevents, 8u);
  ASSERT_EQ(8u, pevents.size());
  ASSERT_TRUE(check_event_table_hit(pevents[0], "t_ingress_1"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_ingress_1",
                                         "_set_port"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_ingress_2"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_ingress_2", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[4], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[5], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[6], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[7], "t_exit", "set_hdr"));
#endif
}

namespace {

struct PreTestConfiguration {
  PreTestConfiguration(McSimplePreLAG *pre, int mgrp,
                       std::initializer_list<int> ports)
      : pre(pre) {
    EXPECT_EQ(McSimplePreLAG::SUCCESS, pre->mc_mgrp_create(mgrp, &mgrp_hdl));
    for (auto port : ports) {
      McSimplePreLAG::PortMap port_map;
      port_map[port] = true;
      McSimplePreLAG::LagMap lag_map;
      node_hdls.emplace_back();
      auto &node_hdl = node_hdls.back();
      EXPECT_EQ(McSimplePreLAG::SUCCESS,
                pre->mc_node_create(port, port_map, lag_map, &node_hdl));
      EXPECT_EQ(McSimplePreLAG::SUCCESS,
                pre->mc_node_associate(mgrp_hdl, node_hdl));
    }
  }

  ~PreTestConfiguration() {
    for (auto node_hdl : node_hdls)
      EXPECT_EQ(McSimplePreLAG::SUCCESS, pre->mc_node_destroy(node_hdl));
    EXPECT_EQ(McSimplePreLAG::SUCCESS, pre->mc_mgrp_destroy(mgrp_hdl));
  }

  McSimplePreLAG *pre;  // non-owning pointer
  McSimplePreLAG::mgrp_hdl_t mgrp_hdl;
  std::vector<McSimplePreLAG::l1_hdl_t> node_hdls;
};

}  // namespace

TEST_F(SimpleSwitch_PacketRedirectP4_BMI, Multicast) {
  static constexpr int port_in = 1;
  static constexpr int mgrp = 1;

  std::vector<MatchKeyParam> match_key;
  match_key.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x02"));
  match_key.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x00", 1));
  ActionData data;
  data.push_back_action_data(mgrp);
  entry_handle_t handle;
  MatchErrorCode rc = test_switch->mt_add_entry(0, "t_ingress_1", match_key,
                                                "_multicast", std::move(data),
                                                &handle);
  ASSERT_EQ(MatchErrorCode::SUCCESS, rc);

  auto pre = test_switch->get_component<McSimplePreLAG>();
  SCOPED_TRACE("SimpleSwitch_PacketRedirectP4_BMI.Multicast");
  PreTestConfiguration pre_config(pre.get(), mgrp, {1, 2});

  const char pkt[] = {'\x02', '\x00', '\x00', '\x00'};
  packet_inject.send(port_in, pkt, sizeof(pkt));
  char recv_buffer[kMaxBufSize];
  int recv_port_1 = -1;
  int recv_port_2 = -1;
  receiver.read(recv_buffer, sizeof(pkt), &recv_port_1);
  // make sure that standard_metadata.packet_length was updated for copies
  ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  receiver.read(recv_buffer, sizeof(pkt), &recv_port_2);
  ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  ASSERT_TRUE((recv_port_1 == 1 && recv_port_2 == 2) ||
              (recv_port_1 == 2 && recv_port_2 == 1));

#ifdef BM_ELOG_ON
  // event check
  std::vector<NNEventListener::NNEvent> pevents;

  events.get_and_remove_events(pid(0), &pevents, 4u);
  ASSERT_EQ(4u, pevents.size());
  ASSERT_TRUE(check_event_table_hit(pevents[0], "t_ingress_1"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_ingress_1",
                                         "_multicast"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_ingress_2"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_ingress_2", "_nop"));

  events.get_and_remove_events(pid(1), &pevents, 4u);
  ASSERT_EQ(4u, pevents.size());
  ASSERT_TRUE(check_event_table_miss(pevents[0], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_exit", "set_hdr"));

  events.get_and_remove_events(pid(2), &pevents, 4u);
  ASSERT_EQ(4u, pevents.size());
  ASSERT_TRUE(check_event_table_miss(pevents[0], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_exit", "set_hdr"));
#endif
}

class SimpleSwitch_PacketRedirectP4_CloneI2E_BMI
    : public SimpleSwitch_PacketRedirectP4_BMI {
 protected:
  void add_entries(int port_out, int mirror_id) {
    std::vector<MatchKeyParam> match_key_1;
    match_key_1.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x03"));
    match_key_1.emplace_back(MatchKeyParam::Type::EXACT,
                             std::string("\x00", 1));
    ActionData data_1;
    data_1.push_back_action_data(port_out);
    entry_handle_t h_1;
    EXPECT_EQ(MatchErrorCode::SUCCESS,
              test_switch->mt_add_entry(0, "t_ingress_1", match_key_1,
                                        "_set_port", std::move(data_1), &h_1));

    std::vector<MatchKeyParam> match_key_2;
    match_key_2.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x03"));
    match_key_2.emplace_back(MatchKeyParam::Type::TERNARY,
                             std::string(4, '\x00'), std::string(4, '\x00'));
    ActionData data_2;
    data_2.push_back_action_data(mirror_id);
    entry_handle_t h_2;
    EXPECT_EQ(MatchErrorCode::SUCCESS,
              test_switch->mt_add_entry(0, "t_ingress_2", match_key_2,
                                        "_clone_i2e", std::move(data_2),
                                        &h_2, 1));
  }
};

TEST_F(SimpleSwitch_PacketRedirectP4_CloneI2E_BMI, CloneI2E) {
  static constexpr int port_in = 1;
  static constexpr int port_out = 2;
  static constexpr int port_out_copy = 3;
  static constexpr int mirror_id = 1;

  add_entries(port_out, mirror_id);

  SimpleSwitch::MirroringSessionConfig config = {};
  config.egress_port = port_out_copy;
  config.egress_port_valid = true;
  test_switch->mirroring_add_session(mirror_id, config);

  const char pkt[] = {'\x03', '\x00', '\x00', '\x00'};
  packet_inject.send(port_in, pkt, sizeof(pkt));
  char recv_buffer[kMaxBufSize];
  int recv_port_1 = -1;
  int recv_port_2 = -1;
  receiver.read(recv_buffer, sizeof(pkt), &recv_port_1);
  // check standard_metadata.packet_length: it should be 2 for the original
  // packet and 4 for the clone
  if (recv_port_1 == port_out) {
    ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  } else {
    ASSERT_EQ(4, static_cast<int>(recv_buffer[1]));
  }
  receiver.read(recv_buffer, sizeof(pkt), &recv_port_2);
  if (recv_port_2 == port_out) {
    ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  } else {
    ASSERT_EQ(4, static_cast<int>(recv_buffer[1]));
  }
  // TODO(antonin): make sure the right packet comes out of the right port
  ASSERT_TRUE((recv_port_1 == port_out && recv_port_2 == port_out_copy) ||
              (recv_port_1 == port_out_copy && recv_port_2 == port_out));

  test_switch->mirroring_delete_session(mirror_id);

#ifdef BM_ELOG_ON
  // event check
  std::vector<NNEventListener::NNEvent> pevents;

  events.get_and_remove_events(pid(0), &pevents, 8u);
  ASSERT_EQ(8u, pevents.size());
  ASSERT_TRUE(check_event_table_hit(pevents[0], "t_ingress_1"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_ingress_1",
                                         "_set_port"));
  ASSERT_TRUE(check_event_table_hit(pevents[2], "t_ingress_2"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_ingress_2",
                                         "_clone_i2e"));
  ASSERT_TRUE(check_event_table_miss(pevents[4], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[5], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[6], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[7], "t_exit", "set_hdr"));

  events.get_and_remove_events(pid(1), &pevents, 4u);
  ASSERT_EQ(4u, pevents.size());
  ASSERT_TRUE(check_event_table_miss(pevents[0], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_exit", "set_hdr"));
#endif
}

TEST_F(SimpleSwitch_PacketRedirectP4_CloneI2E_BMI, CloneI2E_Multicast) {
  static constexpr int port_in = 1;
  static constexpr int port_out = 2;
  static constexpr int port_out_copy = 3;
  static constexpr int port_out_mc_copy = 4;
  static constexpr int mirror_id = 1;
  static constexpr int mgrp = 1;

  add_entries(port_out, mirror_id);

  SimpleSwitch::MirroringSessionConfig config = {};
  config.egress_port = port_out_copy;
  config.egress_port_valid = true;
  config.mgid = mgrp;
  config.mgid_valid = true;
  test_switch->mirroring_add_session(mirror_id, config);

  auto pre = test_switch->get_component<McSimplePreLAG>();
  SCOPED_TRACE("SimpleSwitch_PacketRedirectP4_CloneI2E_BMI.CloneI2E_Multicast");
  PreTestConfiguration pre_config(pre.get(), mgrp, {port_out_mc_copy});

  const char pkt[] = {'\x03', '\x00', '\x00', '\x00'};
  packet_inject.send(port_in, pkt, sizeof(pkt));
  char recv_buffer[kMaxBufSize];
  int recv_port_1 = -1, recv_port_2 = -1, recv_port_3 = -1;
  receiver.read(recv_buffer, sizeof(pkt), &recv_port_1);
  // check standard_metadata.packet_length: it should be 2 for the original
  // packet and 4 for the clone and multicast copies
  if (recv_port_1 == port_out) {
    ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  } else {
    ASSERT_EQ(4, static_cast<int>(recv_buffer[1]));
  }
  receiver.read(recv_buffer, sizeof(pkt), &recv_port_2);
  if (recv_port_2 == port_out) {
    ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  } else {
    ASSERT_EQ(4, static_cast<int>(recv_buffer[1]));
  }
  receiver.read(recv_buffer, sizeof(pkt), &recv_port_3);
  if (recv_port_3 == port_out) {
    ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  } else {
    ASSERT_EQ(4, static_cast<int>(recv_buffer[1]));
  }
  // TODO(antonin): make sure the right packet comes out of the right port
  ASSERT_EQ(std::set<int>({recv_port_1, recv_port_2, recv_port_3}),
            std::set<int>({port_out, port_out_copy, port_out_mc_copy}));

  test_switch->mirroring_delete_session(mirror_id);
  return;

#ifdef BM_ELOG_ON
  // event check
  std::vector<NNEventListener::NNEvent> pevents;

  events.get_and_remove_events(pid(0), &pevents, 8u);
  ASSERT_EQ(8u, pevents.size());
  ASSERT_TRUE(check_event_table_hit(pevents[0], "t_ingress_1"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_ingress_1",
                                         "_set_port"));
  ASSERT_TRUE(check_event_table_hit(pevents[2], "t_ingress_2"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_ingress_2",
                                         "_clone_i2e"));
  ASSERT_TRUE(check_event_table_miss(pevents[4], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[5], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[6], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[7], "t_exit", "set_hdr"));

  events.get_and_remove_events(pid(1), &pevents, 4u);
  ASSERT_EQ(4u, pevents.size());
  ASSERT_TRUE(check_event_table_miss(pevents[0], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_exit", "set_hdr"));

  events.get_and_remove_events(pid(2), &pevents, 4u);
  ASSERT_EQ(4u, pevents.size());
  ASSERT_TRUE(check_event_table_miss(pevents[0], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_exit", "set_hdr"));
#endif
}

class SimpleSwitch_PacketRedirectP4_CloneE2E_BMI
    : public SimpleSwitch_PacketRedirectP4_BMI {
 protected:
  void add_entries(int port_out, int mirror_id) {
    std::vector<MatchKeyParam> match_key_1;
    match_key_1.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x04"));
    match_key_1.emplace_back(MatchKeyParam::Type::EXACT,
                             std::string("\x00", 1));
    ActionData data_1;
    data_1.push_back_action_data(port_out);
    entry_handle_t h_1;
    ASSERT_EQ(MatchErrorCode::SUCCESS,
              test_switch->mt_add_entry(0, "t_ingress_1", match_key_1,
                                        "_set_port", std::move(data_1), &h_1));

    std::vector<MatchKeyParam> match_key_2;
    match_key_2.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x04"));
    // only PKT_INSTANCE_TYPE_NORMAL (= 0)
    match_key_2.emplace_back(MatchKeyParam::Type::TERNARY,
                             std::string(4, '\x00'), std::string(4, '\xff'));
    match_key_2.emplace_back(MatchKeyParam::Type::TERNARY,
                             std::string("\x00", 1), std::string("\xff", 1));
    ActionData data_2;
    data_2.push_back_action_data(mirror_id);
    entry_handle_t h_2;
    ASSERT_EQ(
        MatchErrorCode::SUCCESS,
        test_switch->mt_add_entry(0, "t_egress", match_key_2, "_clone_e2e",
                                  std::move(data_2), &h_2, 1));
  }
};

TEST_F(SimpleSwitch_PacketRedirectP4_CloneE2E_BMI, CloneE2E) {
  static constexpr int port_in = 1;
  static constexpr int port_out = 2;
  static constexpr int port_out_copy = 3;
  static constexpr int mirror_id = 1;

  add_entries(port_out, mirror_id);

  SimpleSwitch::MirroringSessionConfig config = {};
  config.egress_port = port_out_copy;
  config.egress_port_valid = true;
  test_switch->mirroring_add_session(mirror_id, config);

  const char pkt[] = {'\x04', '\x00', '\x00', '\x00'};
  packet_inject.send(port_in, pkt, sizeof(pkt));
  char recv_buffer[kMaxBufSize];
  int recv_port_1 = -1;
  int recv_port_2 = -1;
  receiver.read(recv_buffer, sizeof(pkt), &recv_port_1);
  // check standard_metadata.packet_length
  ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  receiver.read(recv_buffer, sizeof(pkt), &recv_port_2);
  ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  // TODO(antonin): make sure the right packet comes out of the right port
  ASSERT_TRUE((recv_port_1 == port_out && recv_port_2 == port_out_copy) ||
              (recv_port_1 == port_out_copy && recv_port_2 == port_out));

  test_switch->mirroring_delete_session(mirror_id);

#ifdef BM_ELOG_ON
  // event check
  std::vector<NNEventListener::NNEvent> pevents;

  events.get_and_remove_events(pid(0), &pevents, 8u);
  ASSERT_EQ(8u, pevents.size());
  ASSERT_TRUE(check_event_table_hit(pevents[0], "t_ingress_1"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_ingress_1",
                                         "_set_port"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_ingress_2"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_ingress_2", "_nop"));
  ASSERT_TRUE(check_event_table_hit(pevents[4], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[5], "t_egress", "_clone_e2e"));
  ASSERT_TRUE(check_event_table_miss(pevents[6], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[7], "t_exit", "set_hdr"));

  events.get_and_remove_events(pid(1), &pevents, 4u);
  ASSERT_EQ(4u, pevents.size());
  ASSERT_TRUE(check_event_table_miss(pevents[0], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_exit", "set_hdr"));
#endif
}

TEST_F(SimpleSwitch_PacketRedirectP4_CloneE2E_BMI, CloneE2E_Multicast) {
  static constexpr int port_in = 1;
  static constexpr int port_out = 2;
  static constexpr int port_out_copy = 3;
  static constexpr int port_out_mc_copy = 4;
  static constexpr int mirror_id = 1;
  static constexpr int mgrp = 1;

  add_entries(port_out, mirror_id);

  SimpleSwitch::MirroringSessionConfig config = {};
  config.egress_port = port_out_copy;
  config.egress_port_valid = true;
  config.mgid = mgrp;
  config.mgid_valid = true;
  test_switch->mirroring_add_session(mirror_id, config);

  auto pre = test_switch->get_component<McSimplePreLAG>();
  SCOPED_TRACE("SimpleSwitch_PacketRedirectP4_CloneE2E_BMI.CloneE2E_Multicast");
  PreTestConfiguration pre_config(pre.get(), mgrp, {port_out_mc_copy});

  const char pkt[] = {'\x04', '\x00', '\x00', '\x00'};
  packet_inject.send(port_in, pkt, sizeof(pkt));
  char recv_buffer[kMaxBufSize];
  int recv_port_1 = -1, recv_port_2 = -1, recv_port_3 = -1;
  receiver.read(recv_buffer, sizeof(pkt), &recv_port_1);
  // check standard_metadata.packet_length
  ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  receiver.read(recv_buffer, sizeof(pkt), &recv_port_2);
  ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  receiver.read(recv_buffer, sizeof(pkt), &recv_port_3);
  ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  // TODO(antonin): make sure the right packet comes out of the right port
  ASSERT_EQ(std::set<int>({recv_port_1, recv_port_2, recv_port_3}),
            std::set<int>({port_out, port_out_copy, port_out_mc_copy}));

  test_switch->mirroring_delete_session(mirror_id);

#ifdef BM_ELOG_ON
  // event check
  std::vector<NNEventListener::NNEvent> pevents;

  events.get_and_remove_events(pid(0), &pevents, 8u);
  ASSERT_EQ(8u, pevents.size());
  ASSERT_TRUE(check_event_table_hit(pevents[0], "t_ingress_1"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_ingress_1",
                                         "_set_port"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_ingress_2"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_ingress_2", "_nop"));
  ASSERT_TRUE(check_event_table_hit(pevents[4], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[5], "t_egress", "_clone_e2e"));
  ASSERT_TRUE(check_event_table_miss(pevents[6], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[7], "t_exit", "set_hdr"));

  events.get_and_remove_events(pid(1), &pevents, 4u);
  ASSERT_EQ(4u, pevents.size());
  ASSERT_TRUE(check_event_table_miss(pevents[0], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_exit", "set_hdr"));

  events.get_and_remove_events(pid(1), &pevents, 4u);
  ASSERT_EQ(4u, pevents.size());
  ASSERT_TRUE(check_event_table_miss(pevents[0], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_exit", "set_hdr"));
#endif
}

TEST_F(SimpleSwitch_PacketRedirectP4_BMI, Resubmit) {
  /* In this test, the egress port is first set to 2, but because the packet is
     selected for resubmission, and because of the resubmitted metadata, the
     egress port will be set to 3 */
  static constexpr int port_in = 1;
  static constexpr int port_out_1 = 2;
  static constexpr int port_out_2 = 3;

  std::vector<MatchKeyParam> match_key_1;
  match_key_1.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x05"));
  match_key_1.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x00", 1));
  ActionData data_1;
  data_1.push_back_action_data(port_out_1);
  entry_handle_t h_1;
  ASSERT_EQ(MatchErrorCode::SUCCESS,
            test_switch->mt_add_entry(0, "t_ingress_1", match_key_1,
                                      "_set_port", std::move(data_1), &h_1));

  std::vector<MatchKeyParam> match_key_2;
  match_key_2.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x05"));
  match_key_2.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x01", 1));
  ActionData data_2;
  data_2.push_back_action_data(port_out_2);
  entry_handle_t h_2;
  ASSERT_EQ(MatchErrorCode::SUCCESS,
            test_switch->mt_add_entry(0, "t_ingress_1", match_key_2,
                                      "_set_port", std::move(data_2), &h_2));

  std::vector<MatchKeyParam> match_key_3;
  match_key_3.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x05"));
  // only PKT_INSTANCE_TYPE_NORMAL (= 0)
  match_key_3.emplace_back(MatchKeyParam::Type::TERNARY,
                           std::string(4, '\x00'), std::string(4, '\xff'));
  ActionData data_3;
  entry_handle_t h_3;
  ASSERT_EQ(MatchErrorCode::SUCCESS,
            test_switch->mt_add_entry(0, "t_ingress_2", match_key_3,
                                      "_resubmit", std::move(data_3), &h_3, 1));

  const char pkt[] = {'\x05', '\x00', '\x00', '\x00'};
  packet_inject.send(port_in, pkt, sizeof(pkt));
  char recv_buffer[kMaxBufSize];
  int recv_port = -1;
  receiver.read(recv_buffer, sizeof(pkt), &recv_port);
  // check standard_metadata.packet_length
  ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  ASSERT_EQ(port_out_2, recv_port);

#ifdef BM_ELOG_ON
  // event check
  std::vector<NNEventListener::NNEvent> pevents;

  events.get_and_remove_events(pid(0), &pevents, 4u);
  ASSERT_EQ(4u, pevents.size());
  ASSERT_TRUE(check_event_table_hit(pevents[0], "t_ingress_1"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_ingress_1",
                                         "_set_port"));
  ASSERT_TRUE(check_event_table_hit(pevents[2], "t_ingress_2"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_ingress_2",
                                         "_resubmit"));

  // TODO(antonin): if we consider that it is the same packet, then the copy_id
  // should be the same? Update this if this changes in simple_switch
  events.get_and_remove_events(pid(1), &pevents, 8u);
  ASSERT_EQ(8u, pevents.size());
  ASSERT_TRUE(check_event_table_hit(pevents[0], "t_ingress_1"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_ingress_1",
                                         "_set_port"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_ingress_2"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_ingress_2", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[4], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[5], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[6], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[7], "t_exit", "set_hdr"));
#endif
}

TEST_F(SimpleSwitch_PacketRedirectP4_BMI, Recirculate) {
  static constexpr int port_in = 1;
  static constexpr int port_out_1 = 2;
  static constexpr int port_out_2 = 3;

  std::vector<MatchKeyParam> match_key_1;
  match_key_1.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x06"));
  match_key_1.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x00", 1));
  ActionData data_1;
  data_1.push_back_action_data(port_out_1);
  entry_handle_t h_1;
  ASSERT_EQ(MatchErrorCode::SUCCESS,
            test_switch->mt_add_entry(0, "t_ingress_1", match_key_1,
                                      "_set_port", std::move(data_1), &h_1));

  std::vector<MatchKeyParam> match_key_2;
  match_key_2.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x06"));
  match_key_2.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x01", 1));
  ActionData data_2;
  data_2.push_back_action_data(port_out_2);
  entry_handle_t h_2;
  ASSERT_EQ(MatchErrorCode::SUCCESS,
            test_switch->mt_add_entry(0, "t_ingress_1", match_key_2,
                                      "_set_port", std::move(data_2), &h_2));

  std::vector<MatchKeyParam> match_key_3;
  match_key_3.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x06"));
  // only PKT_INSTANCE_TYPE_NORMAL (= 0)
  match_key_3.emplace_back(MatchKeyParam::Type::TERNARY,
                           std::string(4, '\x00'), std::string(4, '\xff'));
  // only 0
  match_key_3.emplace_back(MatchKeyParam::Type::TERNARY,
                           std::string("\x00", 1), std::string("\xff", 1));
  ActionData data_3;
  entry_handle_t h_3;
  ASSERT_EQ(MatchErrorCode::SUCCESS,
            test_switch->mt_add_entry(0, "t_egress", match_key_3,
                                      "_recirculate", std::move(data_3),
                                      &h_3, 1));

  // recirc packet needs to be larger because of remove_header call
  const char pkt[] = {'\x06', '\x00', '\x00', '\x00', '\x00', '\x00'};
  packet_inject.send(port_in, pkt, sizeof(pkt));
  char recv_buffer[kMaxBufSize];
  int recv_port = -1;
  receiver.read(recv_buffer, sizeof(pkt), &recv_port);
  // check standard_metadata.packet_length
  ASSERT_EQ(2, static_cast<int>(recv_buffer[1]));
  ASSERT_EQ(port_out_2, recv_port);

#ifdef BM_ELOG_ON
  // event check
  std::vector<NNEventListener::NNEvent> pevents;

  events.get_and_remove_events(pid(0), &pevents, 8u);
  ASSERT_EQ(8u, pevents.size());
  ASSERT_TRUE(check_event_table_hit(pevents[0], "t_ingress_1"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_ingress_1",
                                         "_set_port"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_ingress_2"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_ingress_2", "_nop"));
  ASSERT_TRUE(check_event_table_hit(pevents[4], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[5], "t_egress",
                                         "_recirculate"));
  ASSERT_TRUE(check_event_table_miss(pevents[6], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[7], "t_exit", "set_hdr"));

  // TODO(antonin): if we consider that it is the same packet, then the copy_id
  // should be the same? Update this if this changes in simple_switch
  events.get_and_remove_events(pid(1), &pevents, 8u);
  ASSERT_EQ(8u, pevents.size());
  ASSERT_TRUE(check_event_table_hit(pevents[0], "t_ingress_1"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_ingress_1",
                                         "_set_port"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_ingress_2"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_ingress_2", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[4], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[5], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[6], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[7], "t_exit", "set_hdr"));
#endif
}

TEST_F(SimpleSwitch_PacketRedirectP4_BMI, ExitIngress) {
  static constexpr int port_in = 1;
  static constexpr int port_out = 0;

  std::vector<MatchKeyParam> match_key_1;
  match_key_1.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x07"));
  match_key_1.emplace_back(MatchKeyParam::Type::EXACT, std::string("\x00", 1));
  ActionData data_1;
  entry_handle_t h_1;
  ASSERT_EQ(MatchErrorCode::SUCCESS,
            test_switch->mt_add_entry(0, "t_ingress_1", match_key_1,
                                      "_exit", std::move(data_1), &h_1));

  const char pkt[] = {'\x07', '\x00', '\x00', '\x00'};
  packet_inject.send(port_in, pkt, sizeof(pkt));
  char recv_buffer[kMaxBufSize];
  int recv_port = -1;
  receiver.read(recv_buffer, sizeof(pkt), &recv_port);
  ASSERT_EQ(port_out, recv_port);

#ifdef BM_ELOG_ON
  // event check
  std::vector<NNEventListener::NNEvent> pevents;

  events.get_and_remove_events(pid(0), &pevents, 6u);
  ASSERT_EQ(6u, pevents.size());
  ASSERT_TRUE(check_event_table_hit(pevents[0], "t_ingress_1"));
  ASSERT_TRUE(check_event_action_execute(pevents[1], "t_ingress_1", "_exit"));
  ASSERT_TRUE(check_event_table_miss(pevents[2], "t_egress"));
  ASSERT_TRUE(check_event_action_execute(pevents[3], "t_egress", "_nop"));
  ASSERT_TRUE(check_event_table_miss(pevents[4], "t_exit"));
  ASSERT_TRUE(check_event_action_execute(pevents[5], "t_exit", "set_hdr"));
#endif
}
