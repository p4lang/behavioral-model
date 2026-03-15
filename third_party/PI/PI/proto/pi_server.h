/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2022 VMware, Inc.
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
 * Antonin Bas
 *
 */

#pragma once

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

// same as the ones defined by gRPC
typedef enum {
  PI_GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE = 0,  // default
  PI_GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_BUT_DONT_VERIFY,
  PI_GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY,
  PI_GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_BUT_DONT_VERIFY,
  PI_GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY,
} PIGrpcServerSSLClientAuth_t;

typedef struct {
  const char *pem_root_certs;
  const char *pem_private_key;
  const char *pem_cert_chain;
  PIGrpcServerSSLClientAuth_t client_auth;
} PIGrpcServerSSLOptions_t;

// Initializes necessary resources. Should only be called once.
void PIGrpcServerInit();

// Same as PIGrpcServerInit but supports providing a serialized
// p4::server::v1::Config Protobuf message (in text format) for P4Runtime server
// configuration.
void PIGrpcServerInitWithConfig(const char *config_text, const char *version);

// Start server and bind to default address (0.0.0.0:9559)
void PIGrpcServerRun();

// Start server and bind to given address (eg. localhost:1234,
// 192.168.1.1:31416, [::1]:27182, etc.)
void PIGrpcServerRunAddr(const char *server_address);

// Start server and bind to given address (eg. localhost:1234,
// 192.168.1.1:31416, [::1]:27182, etc.) and an optional third-party gNMI
// service. Note that the implementation will expect the void* must be a
// pointer of type gnmi::gNMI::Service, and free it as a part of
// PIGrpcServerCleanup
void PIGrpcServerRunAddrGnmi(const char *server_address, void *gnmi_service);

void PIGrpcServerRunV2(const char *server_address,
                       void *gnmi_service,
                       PIGrpcServerSSLOptions_t *ssl_options);

// Get port number bound to the server
int PIGrpcServerGetPort();

// Get number of PacketIn packets sent to client
uint64_t PIGrpcServerGetPacketInCount(uint64_t device_id);

// Get number of PacketOut packets sent to DevMgr
uint64_t PIGrpcServerGetPacketOutCount(uint64_t device_id);

// Wait for the server to shutdown. Note that some other thread must be
// responsible for shutting down the server for this call to ever return.
void PIGrpcServerWait();

// Shutdown server but waits for all RPCs to finish
void PIGrpcServerShutdown();

// Force-shutdown server with a deadline for all RPCs to finish
void PIGrpcServerForceShutdown(int deadline_seconds);

// Once server has been shutdown, cleanup allocated resources.
void PIGrpcServerCleanup();

#ifdef __cplusplus
}
#endif
