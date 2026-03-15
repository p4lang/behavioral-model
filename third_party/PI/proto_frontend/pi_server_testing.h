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

#ifndef PROTO_SERVER_PI_SERVER_TESTING_H_
#define PROTO_SERVER_PI_SERVER_TESTING_H_

#include <PI/frontends/proto/device_mgr.h>

namespace p4 {

namespace v1 {

class PacketIn;

}  // namespace v1

}  // namespace p4

namespace pi {

namespace server {

namespace testing {

void send_packet_in(::pi::fe::proto::DeviceMgr::device_id_t device_id,
                    p4::v1::PacketIn *packet);

size_t max_connections();

}  // namespace testing

}  // namespace server

}  // namespace pi

#endif  // PROTO_SERVER_PI_SERVER_TESTING_H_
