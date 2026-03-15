// Copyright 2019 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "server_config.h"

#include <google/protobuf/text_format.h>

#include <string>

#include "p4/server/v1/config.pb.h"

namespace pi {

namespace fe {

namespace proto {

/* static */
template <typename T>
bool
ServerConfigFromText<T>::parse(const std::string &config_text,
                               T *server_config) {
  return ::google::protobuf::TextFormat::ParseFromString(
      config_text, server_config);
}

template class ServerConfigFromText<p4::server::v1::Config>;

}  // namespace proto

}  // namespace fe

}  // namespace pi

