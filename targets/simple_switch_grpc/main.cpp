/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2022 VMware, Inc.
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

#include <bm/bm_sim/options_parse.h>
#include <bm/bm_sim/target_parser.h>

#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <streambuf>
#include <string>

#include "switch_runner.h"

namespace {

class read_pem_exception : public std::exception {
 public:
  read_pem_exception(const std::string &filename, const std::string &error)
      : filename(filename), error(error) { }

  std::string msg() const {
    std::stringstream ss;
    ss << "Error when reading pem file '" << filename << "': " << error << "\n";
    return ss.str();
  }

  const char *what() const noexcept override {
    return error.c_str();
  }

 private:
  std::string filename;
  std::string error;
};

std::string read_pem_file(const std::string &filename) {
  std::ifstream fs(filename, std::ios::in);
  if (!fs) {
    throw read_pem_exception(filename, "file cannot be opened");
  }
  return std::string((std::istreambuf_iterator<char>(fs)),
                     std::istreambuf_iterator<char>());
}

}  // namespace

int
main(int argc, char* argv[]) {
  bm::TargetParserBasicWithDynModules simple_switch_parser;
  simple_switch_parser.add_flag_option(
      "disable-swap",
      "Disable JSON swapping at runtime; this is not recommended when using "
      "P4Runtime!");
  simple_switch_parser.add_string_option(
      "grpc-server-addr",
      "Bind gRPC server to given address [default is 0.0.0.0:9559]");
  simple_switch_parser.add_flag_option(
      "grpc-server-ssl",
      "Enable SSL/TLS for gRPC server");
  simple_switch_parser.add_string_option(
      "grpc-server-cacert",
      "Path to pem file holding CA certificate to verify peer against");
  simple_switch_parser.add_string_option(
      "grpc-server-cert",
      "Path to pem file holding server certificate");
  simple_switch_parser.add_string_option(
      "grpc-server-key",
      "Path to pem file holding server key");
  simple_switch_parser.add_flag_option(
      "grpc-server-with-client-auth",
      "Require client to have a valid certificate for mutual authentication");
  simple_switch_parser.add_uint_option(
      "cpu-port",
      "Choose a numerical value for the CPU port, it will be used for "
      "packet-in / packet-out. Do not add an interface with this port number, "
      "and 0 is not a valid value. "
      "When using standard v1model.p4, this value must fit within 9 bits. "
      "If you do not use this command-line option, "
      "P4Runtime packet IO functionality will not be available: you will not "
      "be able to receive / send packets using the P4Runtime StreamChannel "
      "bi-directional stream.");
  simple_switch_parser.add_uint_option(
      "drop-port",
      "Choose a numerical value for the drop port (default is 511). "
      "When using standard v1model.p4, this value must fit within 9 bits. "
      "You will need to use this command-line option when you wish to use port "
      "511 as a valid dataplane port or as the CPU port.");
  simple_switch_parser.add_string_option(
      "dp-grpc-server-addr",
      "Use a gRPC channel to inject and receive dataplane packets; "
      "bind this gRPC server to given address, e.g. 0.0.0.0:50052");

  bm::OptionsParser parser;
  parser.parse(argc, argv, &simple_switch_parser);

  std::string dp_grpc_server_addr;
  {
    auto rc = simple_switch_parser.get_string_option(
        "dp-grpc-server-addr", &dp_grpc_server_addr);
    if (rc != bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED &&
        rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
  }

  bool disable_swap_flag = false;
  {
    auto rc = simple_switch_parser.get_flag_option(
        "disable-swap", &disable_swap_flag);
    if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS) std::exit(1);
  }

  std::string grpc_server_addr;
  {
    auto rc = simple_switch_parser.get_string_option(
        "grpc-server-addr", &grpc_server_addr);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      grpc_server_addr = "0.0.0.0:9559";
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
  }

  bool grpc_server_ssl = false;
  {
    auto rc = simple_switch_parser.get_flag_option(
        "grpc-server-ssl", &grpc_server_ssl);
    if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS) std::exit(1);
  }

  std::string grpc_server_cacert;
  {
    auto rc = simple_switch_parser.get_string_option(
        "grpc-server-cacert", &grpc_server_cacert);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      grpc_server_cacert = "";
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
  }

  std::string grpc_server_cert;
  {
    auto rc = simple_switch_parser.get_string_option(
        "grpc-server-cert", &grpc_server_cert);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      grpc_server_cert = "";
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
  }

  std::string grpc_server_key;
  {
    auto rc = simple_switch_parser.get_string_option(
        "grpc-server-key", &grpc_server_key);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      grpc_server_key = "";
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
  }

  bool grpc_server_with_client_auth = false;
  {
    auto rc = simple_switch_parser.get_flag_option(
        "grpc-server-with-client-auth", &grpc_server_with_client_auth);
    if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS) std::exit(1);
  }

  if (!grpc_server_ssl &&
      (grpc_server_cacert != "" ||
       grpc_server_cert != "" ||
       grpc_server_key != "")) {
    std::cerr << "SSL/TLS is disabled for gRPC server, "
        << "so provided .pem files will be ignored\n";
  }

  if (!grpc_server_ssl && grpc_server_with_client_auth) {
    std::cerr << "SSL/TLS is disabled for gRPC server, "
        << "so cannot request client auth\n";
  }

  if (grpc_server_ssl && grpc_server_cert == "") {
    std::cerr << "When enabling SSL/TLS for gRPC server, "
        << "--grpc-server-cert is required\n";
    std::exit(1);
  }
  if (grpc_server_ssl && grpc_server_key == "") {
    std::cerr << "When enabling SSL/TLS for gRPC server, "
        << "--grpc-server-key is required\n";
    std::exit(1);
  }

  uint32_t cpu_port = 0xffffffff;
  {
    auto rc = simple_switch_parser.get_uint_option("cpu-port", &cpu_port);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      cpu_port = 0;
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS || cpu_port == 0)
      std::exit(1);
  }

  uint32_t drop_port = 0xffffffff;
  {
    auto rc = simple_switch_parser.get_uint_option("drop-port", &drop_port);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      drop_port = sswitch_grpc::SimpleSwitchGrpcRunner::default_drop_port;
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
  }

  auto ssl_options = std::make_shared<sswitch_grpc::SSLOptions>();
  try {
    if (grpc_server_ssl) {
      if (grpc_server_cacert != "") {
        ssl_options->pem_root_certs = read_pem_file(grpc_server_cacert);
      }
      if (grpc_server_cert != "") {
        ssl_options->pem_cert_chain = read_pem_file(grpc_server_cert);
      }
      if (grpc_server_key != "") {
        ssl_options->pem_private_key = read_pem_file(grpc_server_key);
      }
      ssl_options->with_client_auth = grpc_server_with_client_auth;
    }
  } catch (const read_pem_exception &e) {
    std::cerr << e.msg();
    std::exit(1);
  }

  auto &runner = sswitch_grpc::SimpleSwitchGrpcRunner::get_instance(
      !disable_swap_flag,
      grpc_server_addr,
      cpu_port,
      dp_grpc_server_addr,
      drop_port,
      grpc_server_ssl ? ssl_options : nullptr);
  int status = runner.init_and_start(parser);
  if (status != 0) std::exit(status);

  runner.wait();
  return 0;
}
