// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <grpcpp/grpcpp.h>

#include <google/rpc/code.pb.h>

#include <fstream>
#include <streambuf>

#include "base_test.h"

namespace p4v1 = ::p4::v1;

namespace pswitch_grpc {

namespace testing {

constexpr char PsaSwitchGrpcBaseTest::grpc_server_addr[];
constexpr char PsaSwitchGrpcBaseTest::dp_grpc_server_addr[];
constexpr int PsaSwitchGrpcBaseTest::cpu_port;
constexpr uint64_t PsaSwitchGrpcBaseTest::device_id;

PsaSwitchGrpcBaseTest::PsaSwitchGrpcBaseTest(
    const char *p4info_proto_txt_path)
    : p4runtime_channel(grpc::CreateChannel(
          grpc_server_addr, grpc::InsecureChannelCredentials())),
      p4runtime_stub(p4v1::P4Runtime::NewStub(p4runtime_channel)) {
  p4info = parse_p4info(p4info_proto_txt_path);
}

void
PsaSwitchGrpcBaseTest::SetUp() {
  stream = p4runtime_stub->StreamChannel(&stream_context);
  p4v1::StreamMessageRequest request;
  auto arbitration = request.mutable_arbitration();
  arbitration->set_device_id(device_id);
  set_election_id(arbitration->mutable_election_id());
  stream->Write(request);
  p4v1::StreamMessageResponse response;
  stream->Read(&response);
  ASSERT_EQ(response.update_case(), p4v1::StreamMessageResponse::kArbitration);
  ASSERT_EQ(response.arbitration().status().code(), ::google::rpc::Code::OK);
}

void
PsaSwitchGrpcBaseTest::TearDown() {
  stream->WritesDone();
  p4v1::StreamMessageResponse response;
  while (stream->Read(&response)) { }
  auto status = stream->Finish();
  EXPECT_TRUE(status.ok());
}

void
PsaSwitchGrpcBaseTest::update_json(const char *json_path) {
  p4v1::SetForwardingPipelineConfigRequest request;
  request.set_device_id(device_id);
  request.set_action(
      p4v1::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT);
  set_election_id(request.mutable_election_id());
  auto config = request.mutable_config();
  std::ifstream istream(json_path);
  ASSERT_TRUE(istream.good());
  config->mutable_p4_device_config()->assign(
      (std::istreambuf_iterator<char>(istream)),
       std::istreambuf_iterator<char>());

  p4v1::SetForwardingPipelineConfigResponse rep;
  ClientContext context;
  config->set_allocated_p4info(&p4info);
  auto status = p4runtime_stub->SetForwardingPipelineConfig(
      &context, request, &rep);
  auto *released_p4info = config->release_p4info();
  ASSERT_EQ(released_p4info, &p4info);
  ASSERT_TRUE(status.ok());
}

void
PsaSwitchGrpcBaseTest::set_election_id(p4v1::Uint128 *election_id) const {
  election_id->set_high(0);
  election_id->set_low(1);
}

grpc::Status
PsaSwitchGrpcBaseTest::write(const p4v1::Entity &entity,
                                p4v1::Update::Type type) const {
  p4v1::WriteRequest request;
  request.set_device_id(device_id);
  auto update = request.add_updates();
  update->set_type(type);
  update->mutable_entity()->CopyFrom(entity);
  ClientContext context;
  p4v1::WriteResponse rep;
  return Write(&context, request, &rep);
}

grpc::Status
PsaSwitchGrpcBaseTest::insert(const p4v1::Entity &entity) const {
  return write(entity, p4v1::Update::INSERT);
}

grpc::Status
PsaSwitchGrpcBaseTest::modify(const p4v1::Entity &entity) const {
  return write(entity, p4v1::Update::MODIFY);
}

grpc::Status
PsaSwitchGrpcBaseTest::remove(const p4v1::Entity &entity) const {
  return write(entity, p4v1::Update::DELETE);
}

grpc::Status
PsaSwitchGrpcBaseTest::read(const p4v1::Entity &entity,
                               p4v1::ReadResponse *rep) const {
  p4v1::ReadRequest request;
  request.set_device_id(device_id);
  request.add_entities()->CopyFrom(entity);
  ClientContext context;
  std::unique_ptr<grpc::ClientReader<p4v1::ReadResponse> > reader(
      p4runtime_stub->Read(&context, request));
  reader->Read(rep);
  return reader->Finish();
}

grpc::Status
PsaSwitchGrpcBaseTest::Write(ClientContext *context,
                                p4v1::WriteRequest &request,
                                p4v1::WriteResponse *response) const {
  request.set_device_id(device_id);
  set_election_id(request.mutable_election_id());
  return p4runtime_stub->Write(context, request, response);
}

}  // namespace testing

}  // namespace pswitch_grpc
