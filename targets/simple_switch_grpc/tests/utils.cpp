/* Copyright 2013-present Barefoot Networks, Inc.
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

#include "utils.h"

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>

#include <fstream>
#include <streambuf>

namespace testing {

int get_table_id(const p4::config::P4Info &p4info,
                 const std::string &t_name) {
  for (const auto &table : p4info.tables()) {
    const auto &pre = table.preamble();
    if (pre.name() == t_name) return pre.id();
  }
  return 0;
}

int get_action_id(const p4::config::P4Info &p4info,
                  const std::string &a_name) {
  for (const auto &action : p4info.actions()) {
    const auto &pre = action.preamble();
    if (pre.name() == a_name) return pre.id();
  }
  return 0;
}

int get_mf_id(const p4::config::P4Info &p4info,
              const std::string &t_name, const std::string &mf_name) {
  for (const auto &table : p4info.tables()) {
    const auto &pre = table.preamble();
    if (pre.name() != t_name) continue;
    for (const auto &mf : table.match_fields())
      if (mf.name() == mf_name) return mf.id();
  }
  return -1;
}

int get_param_id(const p4::config::P4Info &p4info,
                 const std::string &a_name, const std::string &param_name) {
  for (const auto &action : p4info.actions()) {
    const auto &pre = action.preamble();
    if (pre.name() != a_name) continue;
    for (const auto &param : action.params())
      if (param.name() == param_name) return param.id();
  }
  return -1;
}

p4::config::P4Info parse_p4info(const char *path) {
  p4::config::P4Info p4info;
  std::ifstream istream(path);
  // p4info.ParseFromIstream(&istream);
  google::protobuf::io::IstreamInputStream istream_(&istream);
  google::protobuf::TextFormat::Parse(&istream_, &p4info);
  return p4info;
}

}  // namespace testing
