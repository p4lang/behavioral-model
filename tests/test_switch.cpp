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

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <bm/bm_sim/switch.h>
#include <bm/bm_runtime/bm_runtime.h>

#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <thread>
#include <map>

#include "utils.h"

using namespace bm;

namespace fs = boost::filesystem;

namespace {

char char2digit(char c) {
  if (c >= '0' && c <= '9')
    return (c - '0');
  if (c >= 'A' && c <= 'F')
    return (c - 'A' + 10);
  if (c >= 'a' && c <= 'f')
    return (c - 'a' + 10);
  assert(0);
  return 0;
}

}  // namespace

class SwitchTest : public Switch {
 public:
  int receive_(int port_num, const char *buffer, int len) override {
    (void) port_num; (void) buffer; (void) len;
    return 0;
  }

  void start_and_return_() override {
  }

  // needed because the method is protected
  int deserialize(std::istream *in) {
    return Switch::deserialize(in);
  }
};

TEST(Switch, GetConfig) {
  fs::path config_path = fs::path(TESTDATADIR) / fs::path("empty_config.json");
  // the md5 is that file was computed with md5sum on Ubuntu
  fs::path md5_path = fs::path(TESTDATADIR) / fs::path("empty_config.md5");
  std::stringstream config_buffer;
  std::vector<char> md5(16);
  {
    std::ifstream fs(config_path.string());
    config_buffer << fs.rdbuf();
  }
  {
    std::ifstream fs(md5_path.string());
    for (size_t i = 0; i < md5.size(); i++) {
      char c1, c2;
      assert(fs.get(c1)); assert(fs.get(c2));
      md5[i] = (char2digit(c1) << 4) | char2digit(c2);
    }
  }
  SwitchTest sw;
  sw.init_objects(config_path.string(), 0, nullptr);

  ASSERT_EQ(config_buffer.str(), sw.get_config());

  ASSERT_EQ(std::string(md5.begin(), md5.end()), sw.get_config_md5());
}

TEST(Switch, ConfigOptions) {
  fs::path config_path =
      fs::path(TESTDATADIR) / fs::path("config_options.json");
  SwitchTest sw;
  sw.init_objects(config_path.string(), 0, nullptr);

  const auto config_options = sw.get_config_options();
  ASSERT_EQ(2u, config_options.size());
  ASSERT_EQ("aaa", config_options.at("key1"));
  ASSERT_EQ("12345", config_options.at("key2"));
}

TEST(Switch, InitObjectsEmpty) {
  SwitchTest sw;
  ASSERT_EQ(0, sw.init_objects_empty(0, nullptr));
  ASSERT_EQ("{}", sw.get_config());
  sw.enable_config_swap();
  using clock = std::chrono::high_resolution_clock;
  using std::chrono::duration_cast;
  auto start = clock::now();
  std::thread config_push_thread([&sw]{
      std::string new_config("{}");
      sw.load_new_config(new_config);
      std::this_thread::sleep_for(std::chrono::seconds(1));
      sw.swap_configs();
      std::this_thread::sleep_for(std::chrono::seconds(1));
  });
  sw.start_and_return();
  auto end = clock::now();
  config_push_thread.join();
  auto elapsed = duration_cast<std::chrono::milliseconds>(end - start).count();
  EXPECT_NEAR(elapsed, 1000, 500);
}

TEST(Switch, GetP4Objects) {
  // re-using serialize.json here as a convenience
  fs::path config_path = fs::path(TESTDATADIR) / fs::path("serialize.json");
  SwitchTest sw;
  sw.init_objects(config_path.string(), 0, nullptr);

  ASSERT_EQ(nullptr, sw.get_parser("bad_parser"));
  ASSERT_NE(nullptr, sw.get_parser("parser"));

  ASSERT_EQ(nullptr, sw.get_deparser("bad_deparser"));
  ASSERT_NE(nullptr, sw.get_deparser("deparser"));

  ASSERT_EQ(nullptr, sw.get_pipeline("bad_pipeline"));
  ASSERT_NE(nullptr, sw.get_pipeline("ingress"));
}

TEST(Switch, SerializeState1) {
  fs::path config_path = fs::path(TESTDATADIR) / fs::path("serialize.json");
  SwitchTest sw;
  sw.init_objects(config_path.string(), 0, nullptr);
  std::stringstream s1, s2;
  sw.mt_set_default_action(0, "send_frame", "_drop", ActionData());
  sw.mt_set_default_action(0, "forward", "_drop", ActionData());
  sw.mt_set_default_action(0, "ipv4_lpm", "_drop", ActionData());
  sw.serialize(&s1);
  sw.reset_state();
  sw.deserialize(&s1);
  sw.serialize(&s2);
  ASSERT_EQ(s1.str(), s2.str());
}

extern bool WITH_VALGRIND;  // defined in main.cpp

TEST(Switch, SerializeState2) {
  if (WITH_VALGRIND) {
    SUCCEED();
    return;
  }
  fs::path config_path = fs::path(TESTDATADIR) / fs::path("serialize.json");
  SwitchTest sw;
  sw.init_objects(config_path.string(), 0, nullptr);
  int thrift_port = 10999;
  bm_runtime::start_server(&sw, thrift_port);
  std::stringstream s1, s2;
  CLIWrapper CLI(thrift_port, true);
  CLI.send_cmd("table_set_default send_frame _drop");
  CLI.send_cmd("table_set_default forward _drop");
  CLI.send_cmd("table_set_default ipv4_lpm _drop");
  CLI.send_cmd("table_add send_frame rewrite_mac 1 => 00:aa:bb:00:00:00");
  CLI.send_cmd("table_add send_frame rewrite_mac 2 => 00:aa:bb:00:00:01");
  CLI.send_cmd("table_add forward set_dmac 10.0.0.10 => 00:04:00:00:00:00");
  CLI.send_cmd("table_add forward set_dmac 10.0.1.10 => 00:04:00:00:00:01");
  CLI.send_cmd("table_add ipv4_lpm set_nhop 10.0.0.10/32 => 10.0.0.10 1");
  CLI.send_cmd("table_add ipv4_lpm set_nhop 10.0.1.10/32 => 10.0.1.10 2");
  CLI.send_cmd("meter_array_set_rates ipv4_lpm_meter 10000:5000 100000:20000");
  CLI.send_cmd("meter_set_rates port_meter 8 2:5 10:25");
  sw.serialize(&s1);
  sw.reset_state();
  sw.deserialize(&s1);
  sw.serialize(&s2);
  ASSERT_EQ(s1.str(), s2.str());
}

// TODO(antonin): unify the code for these three test cases?
TEST(Switch, ForceArithNone) {
  fs::path config_path = fs::path(TESTDATADIR) / fs::path("one_header.json");
  SwitchTest sw;
  sw.init_objects(config_path.string(), 0, nullptr);
  Packet pkt = sw.new_packet(0, 0, 0, 128, PacketBuffer(256));
  ASSERT_FALSE(pkt.get_phv()->get_field("hdr.f1").get_arith_flag());
  ASSERT_FALSE(pkt.get_phv()->get_field("hdr.f2").get_arith_flag());
  ASSERT_FALSE(pkt.get_phv()->get_field("hdr.f3").get_arith_flag());
}

TEST(Switch, ForceArithField) {
  fs::path config_path = fs::path(TESTDATADIR) / fs::path("one_header.json");
  SwitchTest sw;
  sw.force_arith_field("hdr", "f1");
  sw.init_objects(config_path.string(), 0, nullptr);
  Packet pkt = sw.new_packet(0, 0, 0, 128, PacketBuffer(256));
  ASSERT_TRUE(pkt.get_phv()->get_field("hdr.f1").get_arith_flag());
  ASSERT_FALSE(pkt.get_phv()->get_field("hdr.f2").get_arith_flag());
  ASSERT_FALSE(pkt.get_phv()->get_field("hdr.f3").get_arith_flag());
}

TEST(Switch, ForceArithHeader) {
  fs::path config_path = fs::path(TESTDATADIR) / fs::path("one_header.json");
  SwitchTest sw;
  sw.force_arith_header("hdr");
  sw.init_objects(config_path.string(), 0, nullptr);
  Packet pkt = sw.new_packet(0, 0, 0, 128, PacketBuffer(256));
  ASSERT_TRUE(pkt.get_phv()->get_field("hdr.f1").get_arith_flag());
  ASSERT_TRUE(pkt.get_phv()->get_field("hdr.f2").get_arith_flag());
  ASSERT_TRUE(pkt.get_phv()->get_field("hdr.f3").get_arith_flag());
}

// that's the best place I could find for this test...
TEST(Switch, ExternSafeAccess) {
  fs::path config_path = fs::path(TESTDATADIR) / fs::path("one_extern.json");
  SwitchTest sw;
  sw.init_objects(config_path.string(), 0, nullptr);
  auto context = sw.get_context(0);
  auto extern_wrapper = context->get_extern_instance("extern_1");
  auto extern_instance = extern_wrapper.get();
  ASSERT_NE(nullptr, extern_instance);
}

namespace {

// dummy DevMgrIface implementation for testing
class MyDevMgr : public DevMgrIface {
 public:
  MyDevMgr() { p_monitor = PortMonitorIface::make_dummy(); }

 private:
  bool port_is_up_(port_t) const override { return true; }
  std::map<port_t, PortInfo> get_port_info_() const override {
    return {{99, PortInfo(99, "dummy_port")}};
  }
  ReturnCode port_add_(const std::string &, port_t,
                       const char *, const char *) override {
    return ReturnCode::SUCCESS;
  }
  ReturnCode port_remove_(port_t) override { return ReturnCode::SUCCESS; }
  ReturnCode set_packet_handler_(const PacketHandler &, void *) override {
    return ReturnCode::SUCCESS;
  }
  void transmit_fn_(int, const char *, int) override { }
  void start_() override { }
};

}  // namespace

TEST(Switch, MyDevMgr) {
  std::unique_ptr<MyDevMgr> my_dev_mgr(new MyDevMgr());
  SwitchTest sw;
  int argc = 2;
  char argv0[] = "switch_test";
  char argv1[] = "--no-p4";
  char *argv[] = {argv0, argv1};
  sw.init_from_command_line_options(
      argc, argv, nullptr, nullptr, std::move(my_dev_mgr));

  auto port_info = sw.get_port_info();
  auto dummy_port = port_info.begin()->first;
  EXPECT_EQ(99, dummy_port);
}

TEST(Switch, MyTransport) {
  auto transport = std::make_shared<MemoryAccessor>(1024);
  std::unique_ptr<MyDevMgr> my_dev_mgr(new MyDevMgr());
  SwitchTest sw;
  int argc = 2;
  char argv0[] = "switch_test";
  char argv1[] = "--no-p4";
  char *argv[] = {argv0, argv1};
  sw.init_from_command_line_options(
      argc, argv, nullptr, transport, std::move(my_dev_mgr));
  sw.transport_send_probe(0xaba);
  struct msg_t {
    char sub_topic[4];
    int switch_id;
    uint64_t x;
    char _padding[16];  // the header size for notifications is always 32 bytes
  } __attribute__((packed));
  msg_t msg;
  transport->read(reinterpret_cast<char *>(&msg), sizeof(msg));
  EXPECT_EQ(0xaba, msg.x);
}
