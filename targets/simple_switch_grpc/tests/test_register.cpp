// SPDX-FileCopyrightText: 2026 Lorenzo Rinieri
//
// SPDX-License-Identifier: Apache-2.0

#include <google/rpc/status.pb.h>
#include <grpcpp/grpcpp.h>

#include <p4/bm/dataplane_interface.grpc.pb.h>
#include <p4/v1/p4runtime.grpc.pb.h>

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "base_test.h"

namespace p4v1 = ::p4::v1;

namespace sswitch_grpc {

namespace testing {

namespace {

constexpr char register_json[] = TESTDATADIR "/register.json";
constexpr char register_proto[] = TESTDATADIR "/register.proto.txt";

// P4Runtime reports a failed Write as UNKNOWN, with one p4.v1.Error per update
// in the details; this returns the code of the only update
grpc::StatusCode write_error_code(const grpc::Status &status) {
  if (status.error_code() != grpc::StatusCode::UNKNOWN)
    return status.error_code();
  google::rpc::Status rpc_status;
  p4v1::Error error;
  if (!rpc_status.ParseFromString(status.error_details()) ||
      rpc_status.details_size() != 1 ||
      !rpc_status.details(0).UnpackTo(&error)) {
    return grpc::StatusCode::UNKNOWN;
  }
  return static_cast<grpc::StatusCode>(error.canonical_code());
}

// For each register, the P4 program writes cell 0 + 1 to cell 1 for every
// packet, and sends the packet back to its ingress port.
class SimpleSwitchGrpcTest_Register : public SimpleSwitchGrpcBaseTest {
 protected:
  SimpleSwitchGrpcTest_Register()
      : SimpleSwitchGrpcBaseTest(register_proto),
        dataplane_channel(grpc::CreateChannel(
            dp_grpc_server_addr, grpc::InsecureChannelCredentials())),
        dataplane_stub(p4::bm::DataplaneInterface::NewStub(
            dataplane_channel)) { }

  void SetUp() override {
    SimpleSwitchGrpcBaseTest::SetUp();
    update_json(register_json);
    r16_id = get_register_id(p4info, "ingress.r16");
    r_wide_id = get_register_id(p4info, "ingress.r_wide");
  }

  // a negative index means all the cells
  static p4v1::Entity make_entity(int register_id, int index) {
    p4v1::Entity entity;
    auto *register_entry = entity.mutable_register_entry();
    register_entry->set_register_id(register_id);
    if (index >= 0) register_entry->mutable_index()->set_index(index);
    return entity;
  }

  grpc::Status write_register(int register_id, int index,
                              const std::string &value) const {
    auto entity = make_entity(register_id, index);
    entity.mutable_register_entry()->mutable_data()->set_bitstring(value);
    return modify(entity);
  }

  grpc::Status read_register(int register_id, int index,
                             p4v1::ReadResponse *response) const {
    return read(make_entity(register_id, index), response);
  }

  // returns the bitstring of the only cell in the response
  std::string read_one_cell(int register_id, int index) const {
    p4v1::ReadResponse response;
    auto status = read_register(register_id, index, &response);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(1, response.entities_size());
    if (response.entities_size() != 1) return "";
    const auto &register_entry = response.entities(0).register_entry();
    EXPECT_EQ(register_id, static_cast<int>(register_entry.register_id()));
    EXPECT_EQ(index, register_entry.index().index());
    return register_entry.data().bitstring();
  }

  void send_one_packet() {
    p4::bm::PacketStreamRequest packet_request;
    packet_request.set_device_id(device_id);
    packet_request.set_port(1);
    packet_request.set_packet(std::string(10, '\xab'));

    ClientContext context;
    auto stream = dataplane_stub->PacketStream(&context);
    stream->Write(packet_request);
    p4::bm::PacketStreamResponse packet_response;
    stream->Read(&packet_response);
    EXPECT_EQ(packet_request.port(), packet_response.port());
    EXPECT_EQ(packet_request.packet(), packet_response.packet());
    stream->WritesDone();
    auto status = stream->Finish();
    EXPECT_TRUE(status.ok());
  }

  std::shared_ptr<grpc::Channel> dataplane_channel{nullptr};
  std::unique_ptr<p4::bm::DataplaneInterface::Stub> dataplane_stub{nullptr};
  int r16_id{0};
  int r_wide_id{0};
};

TEST_F(SimpleSwitchGrpcTest_Register, WriteAndRead) {
  EXPECT_TRUE(write_register(r16_id, 3, "\x12\x34").ok());
  EXPECT_EQ(std::string("\x12\x34"), read_one_cell(r16_id, 3));

  // 160-bit cell: wider than the 64-bit values of the bmv2 Thrift API
  const std::string wide_value(
      "\x80\x01\x02\x03\x04\x05\x06\x07\x08\x09"
      "\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\xff", 20);
  EXPECT_TRUE(write_register(r_wide_id, 2, wide_value).ok());
  EXPECT_EQ(wide_value, read_one_cell(r_wide_id, 2));

  // reads return canonical bytestrings
  EXPECT_TRUE(
      write_register(r_wide_id, 2, std::string("\x00\x00\x05", 3)).ok());
  EXPECT_EQ(std::string("\x05"), read_one_cell(r_wide_id, 2));
  EXPECT_TRUE(write_register(r16_id, 3, std::string("\x00", 1)).ok());
  EXPECT_EQ(std::string("\x00", 1), read_one_cell(r16_id, 3));
}

// the data plane sees the values written over P4Runtime, and P4Runtime reads
// the values written by the data plane
TEST_F(SimpleSwitchGrpcTest_Register, DataPlane) {
  EXPECT_TRUE(write_register(r16_id, 0, "\x12\x34").ok());
  // the increment carries over bit 64
  EXPECT_TRUE(write_register(r_wide_id, 0, std::string(8, '\xff')).ok());
  send_one_packet();
  EXPECT_EQ(std::string("\x12\x35"), read_one_cell(r16_id, 1));
  EXPECT_EQ(std::string("\x01\x00\x00\x00\x00\x00\x00\x00\x00", 9),
            read_one_cell(r_wide_id, 1));

  // the increment wraps around
  EXPECT_TRUE(write_register(r16_id, 0, "\xff\xff").ok());
  send_one_packet();
  EXPECT_EQ(std::string("\x00", 1), read_one_cell(r16_id, 1));
}

TEST_F(SimpleSwitchGrpcTest_Register, WildcardRead) {
  for (int i = 0; i < 8; i++)
    EXPECT_TRUE(write_register(r16_id, i, std::string(1, 'a' + i)).ok());
  {
    p4v1::ReadResponse response;
    EXPECT_TRUE(read_register(r16_id, -1, &response).ok());
    ASSERT_EQ(8, response.entities_size());
    for (int i = 0; i < 8; i++) {
      const auto &register_entry = response.entities(i).register_entry();
      EXPECT_EQ(r16_id, static_cast<int>(register_entry.register_id()));
      EXPECT_EQ(i, register_entry.index().index());
      EXPECT_EQ(std::string(1, 'a' + i), register_entry.data().bitstring());
    }
  }
  {
    // register_id 0 means all the registers
    p4v1::ReadResponse response;
    EXPECT_TRUE(read_register(0, -1, &response).ok());
    EXPECT_EQ(8 + 4, response.entities_size());
  }
}

TEST_F(SimpleSwitchGrpcTest_Register, InvalidIndex) {
  EXPECT_EQ(grpc::StatusCode::OUT_OF_RANGE,
            write_error_code(write_register(r16_id, 8, "\x01")));
  p4v1::ReadResponse response;
  EXPECT_EQ(grpc::StatusCode::OUT_OF_RANGE,
            read_register(r_wide_id, 4, &response).error_code());
}

}  // namespace

}  // namespace testing

}  // namespace sswitch_grpc
