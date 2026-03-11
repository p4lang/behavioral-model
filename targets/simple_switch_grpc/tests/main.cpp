// Copyright 2026 Prakash Kumar

#include <signal.h>
#include <stdlib.h>

#include <iostream>

#include <gtest/gtest.h>

namespace sswitch_grpc {
namespace testing {

class SimpleSwitchGrpcEnv : public ::testing::Environment {
 public:
  void SetUp() override {
    auto &runner = SimpleSwitchGrpcRunner::get_instance(
        true,
        SimpleSwitchGrpcBaseTest::grpc_server_addr,
        SimpleSwitchGrpcBaseTest::cpu_port,
        SimpleSwitchGrpcBaseTest::dp_grpc_server_addr);

    bm::OptionsParser parser;

    std::vector<const char *> argv = {"test", "--device-id", "3"};

#ifdef WITH_THRIFT
    argv.push_back("--thrift-port");
    argv.push_back("45459");
#endif

    argv.push_back("--log-console");
    argv.push_back(TESTDATADIR "/loopback.json");

    auto argc = static_cast<int>(argv.size());

    parser.parse(argc, const_cast<char **>(argv.data()), nullptr);

    ASSERT_EQ(0, runner.init_and_start(parser));
  }

  void TearDown() override {
    SimpleSwitchGrpcRunner::get_instance().shutdown();
  }
};

}  // namespace testing
}  // namespace sswitch_grpc

int main(int argc, char *argv[]) {
  ::testing::InitGoogleTest(&argc, argv);

  ::testing::AddGlobalTestEnvironment(
      new sswitch_grpc::testing::SimpleSwitchGrpcEnv);

  return RUN_ALL_TESTS();
}

