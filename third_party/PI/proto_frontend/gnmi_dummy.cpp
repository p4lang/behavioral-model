/* Copyright 2013-present Barefoot Networks, Inc.
 * SPDX-License-Identifier: Apache-2.0
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

#include <grpcpp/grpcpp.h>

#include "gnmi.h"
#include "gnmi/gnmi.grpc.pb.h"
#include "log.h"

using grpc::ServerContext;
using grpc::ServerReaderWriter;
using grpc::Status;
using grpc::StatusCode;

namespace pi {

namespace server {

class gNMIServiceImpl : public gnmi::gNMI::Service {
 private:
  Status Capabilities(ServerContext *context,
                      const gnmi::CapabilityRequest *request,
                      gnmi::CapabilityResponse *response) override {
    (void) context; (void) request; (void) response;
    SIMPLELOG << "gNMI Capabilities\n";
    SIMPLELOG << request->DebugString();
    return Status(StatusCode::UNIMPLEMENTED, "not implemented");
  }

  Status Get(ServerContext *context, const gnmi::GetRequest *request,
             gnmi::GetResponse *response) override {
    (void) context; (void) request; (void) response;
    SIMPLELOG << "gNMI Get\n";
    SIMPLELOG << request->DebugString();
    return Status(StatusCode::UNIMPLEMENTED, "not implemented");
  }

  Status Set(ServerContext *context, const gnmi::SetRequest *request,
             gnmi::SetResponse *response) override {
    (void) context; (void) request; (void) response;
    SIMPLELOG << "gNMI Set\n";
    SIMPLELOG << request->DebugString();
    return Status(StatusCode::UNIMPLEMENTED, "not implemented");
  }

  Status Subscribe(
      ServerContext *context,
      ServerReaderWriter<gnmi::SubscribeResponse,
                         gnmi::SubscribeRequest> *stream) override {
    (void) context;
    SIMPLELOG << "gNMI Subscribe\n";
    gnmi::SubscribeRequest request;
    // keeping the channel open, but not doing anything
    // if we receive a Write, we will return an error status
    while (stream->Read(&request)) {
      return Status(StatusCode::UNIMPLEMENTED, "not implemented yet");
    }
    return Status::OK;
  }
};

std::unique_ptr<gnmi::gNMI::Service> make_gnmi_service_dummy() {
  return std::unique_ptr<gnmi::gNMI::Service>(new gNMIServiceImpl());
}

}  // namespace server

}  // namespace pi
