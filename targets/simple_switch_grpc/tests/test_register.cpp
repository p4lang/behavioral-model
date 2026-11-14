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

// For each register, the P4 program writes a value computed from cell 0 to cell
// 1 for every packet (see register.p4), and sends the packet back to its
// ingress port.
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
    r_int_id = get_register_id(p4info, "ingress.r_int");
    r_color_id = get_register_id(p4info, "ingress.r_color");
    r_shape_id = get_register_id(p4info, "ingress.r_shape");
    r_id_id = get_register_id(p4info, "ingress.r_id");
  }

  // a negative index means all the cells
  static p4v1::Entity make_entity(int register_id, int index) {
    p4v1::Entity entity;
    auto *register_entry = entity.mutable_register_entry();
    register_entry->set_register_id(register_id);
    if (index >= 0) register_entry->mutable_index()->set_index(index);
    return entity;
  }

  grpc::Status write_data(int register_id, int index,
                          const p4v1::P4Data &data) const {
    auto entity = make_entity(register_id, index);
    entity.mutable_register_entry()->mutable_data()->CopyFrom(data);
    return modify(entity);
  }

  grpc::Status write_register(int register_id, int index,
                              const std::string &value) const {
    return write_data(register_id, index, bitstring(value));
  }

  grpc::Status read_register(int register_id, int index,
                             p4v1::ReadResponse *response) const {
    return read(make_entity(register_id, index), response);
  }

  // returns the data of the only cell in the response
  p4v1::P4Data read_one_data(int register_id, int index) const {
    p4v1::ReadResponse response;
    auto status = read_register(register_id, index, &response);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(1, response.entities_size());
    if (response.entities_size() != 1) return p4v1::P4Data();
    const auto &register_entry = response.entities(0).register_entry();
    EXPECT_EQ(register_id, static_cast<int>(register_entry.register_id()));
    EXPECT_EQ(index, register_entry.index().index());
    return register_entry.data();
  }

  // returns the bitstring of the only cell in the response
  std::string read_one_cell(int register_id, int index) const {
    return read_one_data(register_id, index).bitstring();
  }

  static p4v1::P4Data bitstring(const std::string &value) {
    p4v1::P4Data data;
    data.set_bitstring(value);
    return data;
  }

  static p4v1::P4Data enum_value(const std::string &value) {
    p4v1::P4Data data;
    data.set_enum_value(value);
    return data;
  }

  static p4v1::P4Data enum_member(const std::string &name) {
    p4v1::P4Data data;
    data.set_enum_(name);
    return data;
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
  int r16_id{0};  // bit<16>, 8 cells
  int r_wide_id{0};  // bit<160>, 4 cells
  int r_int_id{0};  // int<16>, 4 cells
  int r_color_id{0};  // serializable enum color_t (bit<8>), 4 cells
  int r_shape_id{0};  // enum shape_t, 4 cells
  int r_id_id{0};  // type bit<20> id_t, 4 cells
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
    EXPECT_EQ(8 + 5 * 4, response.entities_size());
  }
}

// the same value is written to every cell
TEST_F(SimpleSwitchGrpcTest_Register, WildcardWrite) {
  EXPECT_TRUE(write_register(r16_id, -1, "\x12\x34").ok());
  p4v1::ReadResponse response;
  EXPECT_TRUE(read_register(r16_id, -1, &response).ok());
  ASSERT_EQ(8, response.entities_size());
  for (const auto &entity : response.entities()) {
    EXPECT_EQ(std::string("\x12\x34"),
              entity.register_entry().data().bitstring());
  }
  send_one_packet();
  EXPECT_EQ(std::string("\x12\x35"), read_one_cell(r16_id, 1));

  EXPECT_TRUE(write_data(r_shape_id, -1, enum_member("TRIANGLE")).ok());
  for (int i = 0; i < 4; i++)
    EXPECT_EQ("TRIANGLE", read_one_data(r_shape_id, i).enum_());
}

// int<16>: cell 1 is cell 0 - 1, and cell 2 is cell 0 >> 1 (arithmetic shift)
TEST_F(SimpleSwitchGrpcTest_Register, SignedInt) {
  EXPECT_TRUE(write_register(r_int_id, 0, "\xfc").ok());  // -4
  EXPECT_EQ(std::string("\xfc"), read_one_cell(r_int_id, 0));
  send_one_packet();
  EXPECT_EQ(std::string("\xfb"), read_one_cell(r_int_id, 1));  // -5
  EXPECT_EQ(std::string("\xfe"), read_one_cell(r_int_id, 2));  // -2

  // sign-extended bytestrings are accepted
  EXPECT_TRUE(write_register(r_int_id, 0, "\xff\xff\xff\xf6").ok());  // -10
  EXPECT_EQ(std::string("\xf6"), read_one_cell(r_int_id, 0));
  EXPECT_TRUE(write_register(
      r_int_id, 0, std::string("\x00\x00\x7f\xff", 4)).ok());  // 32767
  send_one_packet();
  EXPECT_EQ(std::string("\x7f\xfe"), read_one_cell(r_int_id, 1));
  EXPECT_EQ(std::string("\x3f\xff"), read_one_cell(r_int_id, 2));

  // -32768 - 1 wraps around
  EXPECT_TRUE(write_register(r_int_id, 0, std::string("\x80\x00", 2)).ok());
  send_one_packet();
  EXPECT_EQ(std::string("\x7f\xff"), read_one_cell(r_int_id, 1));
  EXPECT_EQ(std::string("\xc0\x00", 2), read_one_cell(r_int_id, 2));

  // 32768 does not fit in an int<16>
  EXPECT_EQ(grpc::StatusCode::INVALID_ARGUMENT,
            write_error_code(write_register(
                r_int_id, 0, std::string("\x00\x80\x00", 3))));
}

// cell 1 is BLUE if cell 0 is GREEN, RED otherwise
TEST_F(SimpleSwitchGrpcTest_Register, SerializableEnum) {
  EXPECT_TRUE(write_data(r_color_id, 0, enum_value("\x02")).ok());  // GREEN
  EXPECT_EQ("\x02", read_one_data(r_color_id, 0).enum_value());
  send_one_packet();
  EXPECT_EQ("\x03", read_one_data(r_color_id, 1).enum_value());

  // a value without a name
  EXPECT_TRUE(write_data(r_color_id, 0, enum_value("\x07")).ok());
  send_one_packet();
  EXPECT_EQ("\x01", read_one_data(r_color_id, 1).enum_value());

  EXPECT_EQ(grpc::StatusCode::INVALID_ARGUMENT,
            write_error_code(write_register(r_color_id, 0, "\x02")));
}

// cell 1 is TRIANGLE if cell 0 is SQUARE, CIRCLE otherwise
TEST_F(SimpleSwitchGrpcTest_Register, Enum) {
  // cells are initialized to the first member
  EXPECT_EQ("CIRCLE", read_one_data(r_shape_id, 0).enum_());

  EXPECT_TRUE(write_data(r_shape_id, 0, enum_member("SQUARE")).ok());
  EXPECT_EQ("SQUARE", read_one_data(r_shape_id, 0).enum_());
  send_one_packet();
  EXPECT_EQ("TRIANGLE", read_one_data(r_shape_id, 1).enum_());

  EXPECT_TRUE(write_data(r_shape_id, 0, enum_member("TRIANGLE")).ok());
  send_one_packet();
  EXPECT_EQ("CIRCLE", read_one_data(r_shape_id, 1).enum_());

  EXPECT_EQ(grpc::StatusCode::INVALID_ARGUMENT,
            write_error_code(write_data(r_shape_id, 0,
                                        enum_member("HEXAGON"))));
}

// type bit<20> id_t: cell 1 is cell 0 + 1
TEST_F(SimpleSwitchGrpcTest_Register, NewType) {
  EXPECT_TRUE(write_register(r_id_id, 0, "\x0f\xff\xff").ok());
  EXPECT_EQ(std::string("\x0f\xff\xff"), read_one_cell(r_id_id, 0));
  send_one_packet();
  // the increment wraps around at 20 bits
  EXPECT_EQ(std::string("\x00", 1), read_one_cell(r_id_id, 1));

  EXPECT_EQ(grpc::StatusCode::INVALID_ARGUMENT,
            write_error_code(write_register(
                r_id_id, 0, std::string("\x10\x00\x00", 3))));
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
