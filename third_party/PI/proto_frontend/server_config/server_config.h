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

#ifndef SRC_SERVER_CONFIG_H_
#define SRC_SERVER_CONFIG_H_

#include <mutex>
#include <string>
#include <type_traits>  // for std::result_of

#include "p4/server/v1/config.pb.h"

namespace pi {

namespace fe {

namespace proto {

template <typename T>
class ServerConfigFromText {
 public:
  static bool parse(const std::string &config_text,
                    T *server_config);
};

class ServerConfigAccessor {
 public:
  ServerConfigAccessor() { }

  explicit ServerConfigAccessor(const p4::server::v1::Config &server_config)
      : config(server_config) { }

  // Usage:
  // auto enable_error_reporting = this->get(
  //   [](const p4::server::v1::Config &config) {
  //     return config.stream().error_reporting() > 0;
  //   }
  // );
  template <typename Fn>
  typename std::result_of<Fn(p4::server::v1::Config &)>::type
  get(Fn fn) const {
    Lock lock(m);
    return fn(config);
  }

  void set_config(const p4::server::v1::Config &server_config) {
    Lock lock(m);
    config = server_config;
  }

  p4::server::v1::Config get_config() const {
    Lock lock(m);
    return config;
  }

 private:
  using Mutex = std::mutex;
  using Lock = std::lock_guard<Mutex>;

  mutable Mutex m;
  p4::server::v1::Config config;
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_SERVER_CONFIG_H_

