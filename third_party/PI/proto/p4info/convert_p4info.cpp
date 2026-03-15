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

#include <PI/p4info.h>

#include <unistd.h>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>

#include <fstream>  // std::ifstream, std::ofstream
#include <iostream>
#include <string>

#include "PI/proto/p4info_to_and_from_proto.h"

#include "p4/config/v1/p4info.pb.h"

namespace {

void print_help(const char *prog_name) {
  std::cerr << "Usage: " << prog_name << " [OPTIONS]...\n"
            << "Utility to convert P4Info proto from and to other formats\n\n"
            << "-f          format of source (from)\n"
            << "            one of 'bmv2', 'native', 'proto', 'prototext'\n"
            << "-t          desired format of destination dir (to)\n"
            << "            one of 'native', 'proto', 'prototext'\n"
            << "-i          path to input config\n"
            << "-o          path where to write output\n";
}

char *from = NULL;
char *to = NULL;
char *input_path = NULL;
char *output_path = NULL;

int parse_opts(int argc, char *argv[]) {
  int c;

  opterr = 0;

  while ((c = getopt(argc, argv, "i:o:f:t:h")) != -1) {
    switch (c) {
      case 'i':
        input_path = optarg;
        break;
      case 'o':
        output_path = optarg;
        break;
      case 'f':
        from = optarg;
        break;
      case 't':
        to = optarg;
        break;
      case 'h':
        print_help(argv[0]);
        exit(0);
      case '?':
        if (optopt == 'i' || optopt == 'o' ||optopt == 'f' || optopt == 't') {
          std::cerr << "Option -" << static_cast<char>(optopt)
                    << " requires an argument.\n\n";
          print_help(argv[0]);
        } else if (isprint(optopt)) {
          std::cerr << "Unknown option -" << static_cast<char>(optopt)
                    << ".\n\n";
          print_help(argv[0]);
        } else {
          std::cerr << "Unknown option character.\n\n";
          print_help(argv[0]);
        }
        return 1;
      default:
        abort();
    }
  }

  if (!input_path || !output_path || !from || !to) {
    fprintf(stderr, "Options -f, -t, -i and -o are ALL required.\n\n");
    print_help(argv[0]);
    return 1;
  }

  return 0;
}

}  // namespace

int main(int argc, char *argv[]) {
  int rc;
  if ((rc = parse_opts(argc, argv)) != 0) return rc;

  std::string from_str(from);
  std::string to_str(to);
  std::string input_path_str(input_path);
  std::string output_path_str(output_path);

  pi_p4info_t *p4info;
  if (from_str == "bmv2" || from_str == "native") {
    pi_status_t status;
    if (from_str == "bmv2") {
      status = pi_add_config_from_file(input_path, PI_CONFIG_TYPE_BMV2_JSON,
                                       &p4info);
    } else {
      status = pi_add_config_from_file(input_path, PI_CONFIG_TYPE_NATIVE_JSON,
                                       &p4info);
    }
    if (status != PI_STATUS_SUCCESS) {
      std::cerr << "Error when loading input config.\n";
      return 1;
    }
  } else if (from_str == "proto") {
    p4::config::v1::P4Info p4info_proto;
    std::ifstream is(input_path_str, std::ifstream::binary);
    if (!is) {
      std::cerr << "Error while opening protobuf input file.\n";
      return 1;
    }
    auto status = p4info_proto.ParseFromIstream(&is);
    if (!status) {
      std::cerr << "Error while importing protobuf message.\n";
      return 1;
    }
    if (!pi::p4info::p4info_proto_reader(p4info_proto, &p4info)) {
      std::cerr << "Error while importing protobuf message to p4info.\n";
      return 1;
    }
  } else if (from_str == "prototext") {
    p4::config::v1::P4Info p4info_proto;
    std::ifstream is(input_path_str);
    if (!is) {
      std::cerr << "Error while opening protobuf text input file.\n";
      return 1;
    }
    google::protobuf::io::IstreamInputStream is_(&is);
    auto status = google::protobuf::TextFormat::Parse(&is_, &p4info_proto);
    if (!status) {
      std::cerr << "Error while importing protobuf text message.\n";
      return 1;
    }
    if (!pi::p4info::p4info_proto_reader(p4info_proto, &p4info)) {
      std::cerr << "Error while importing protobuf message to p4info.\n";
      return 1;
    }
  } else {
    std::cerr << "Invalid value for -f option.\n";
    return 1;
  }

  std::ofstream os(output_path_str, std::ofstream::binary);
  if (!os) {
    std::cerr << "Error while opening output file.\n";
    return 1;
  }
  if (to_str == "native") {
    char *native_json = pi_serialize_config(p4info, 1);
    std::cout << native_json << "\n";
    os << native_json << "\n";
    pi_free_serialized_config(native_json);
  } else if (to_str == "proto") {
    const auto p4info_proto = pi::p4info::p4info_serialize_to_proto(p4info);
    std::cout << p4info_proto.DebugString();
    p4info_proto.SerializeToOstream(&os);
  } else if (to_str == "prototext") {
    const auto p4info_proto = pi::p4info::p4info_serialize_to_proto(p4info);
    std::cout << p4info_proto.DebugString();
    google::protobuf::io::OstreamOutputStream os_(&os);
    auto status = google::protobuf::TextFormat::Print(p4info_proto, &os_);
    if (!status) {
      std::cerr << "Error while writing protobuf text file.\n";
      return 1;
    }
  } else {
    std::cerr << "Invalid value for -t option.\n";
    return 1;
  }

  pi_destroy_config(p4info);
}
