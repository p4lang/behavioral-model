// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/options_parse.h>

#include <gtest/gtest.h>

#include <vector>

#include "base_test.h"
#include "switch_runner.h"

namespace sswitch_grpc {

namespace testing {

namespace {

constexpr char start_json[] = TESTDATADIR "/loopback.json";

class SimpleSwitchGrpcEnv : public ::testing::Environment {
 public:
  // We make the switch a shared resource for all tests. This is mainly because
  // simple_switch detaches threads.
  // TODO(antonin): the issue with this is that tests may affect each other; in
  // particular tests which modify port operational status.
  void SetUp() override {
    auto &runner = SimpleSwitchGrpcRunner::get_instance(
        true, SimpleSwitchGrpcBaseTest::grpc_server_addr,
        SimpleSwitchGrpcBaseTest::cpu_port,
        SimpleSwitchGrpcBaseTest::dp_grpc_server_addr);
    bm::OptionsParser parser;
    std::vector<const char *> argv = {"test", "--device-id", "3"};
#ifdef WITH_THRIFT
    argv.push_back("--thrift-port");
    argv.push_back("45459");
#endif  // WITH_THRIFT
    // you can uncomment this when debugging
    argv.push_back("--log-console");
    argv.push_back(start_json);
    auto argc = static_cast<int>(argv.size());
    parser.parse(argc, const_cast<char **>(argv.data()), nullptr);
    ASSERT_EQ(0, runner.init_and_start(parser));
  }

  void TearDown() override {
    SimpleSwitchGrpcRunner::get_instance().shutdown();
  }
};

}  // namespace

}  // namespace testing

}  // namespace sswitch_grpc

int main(int argc, char *argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  ::testing::AddGlobalTestEnvironment(
       new sswitch_grpc::testing::SimpleSwitchGrpcEnv);
  return RUN_ALL_TESTS();
}
