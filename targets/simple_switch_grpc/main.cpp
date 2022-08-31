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
#include <bm/bm_grpc/pem.h>

#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <streambuf>
#include <string>

#include "simple_switch.h"
#include "switch_runner.h"


#ifdef WITH_SYSREPO
#include "switch_sysrepo.h"
#endif // WITH_SYSREPO


#ifdef WITH_THRIFT
#include <bm/SimpleSwitch.h>
#include <bm/bm_runtime/bm_runtime.h>

namespace sswitch_runtime {
    shared_ptr<SimpleSwitchIf> get_handler(SimpleSwitch *sw);
}  // namespace sswitch_runtime
#endif  // WITH_THRIFT


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
  simple_switch_parser.add_uint_option(
    "priority-queues",
    "Number of priority queues (default is 1)");

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
      drop_port = switch_runner::SwitchGrpcRunner::default_drop_port;
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
  }

  auto ssl_options = std::make_shared<SSLOptions>();
  try {
    if (grpc_server_ssl) {
      if (grpc_server_cacert != "") {
        ssl_options->pem_root_certs = bm::read_pem_file(grpc_server_cacert);
      }
      if (grpc_server_cert != "") {
        ssl_options->pem_cert_chain = bm::read_pem_file(grpc_server_cert);
      }
      if (grpc_server_key != "") {
        ssl_options->pem_private_key = bm::read_pem_file(grpc_server_key);
      }
      ssl_options->with_client_auth = grpc_server_with_client_auth;
    }
  } catch (const bm::read_pem_exception &e) {
    std::cerr << e.msg();
    std::exit(1);
  }

  uint32_t priority_queues = 0xffffffff;
  {
    auto rc = simple_switch_parser.get_uint_option("priority-queues",
                                                   &priority_queues);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      priority_queues =
          switch_runner::SwitchGrpcRunner::default_nb_queues_per_port;
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
  }

  std::shared_ptr<SimpleSwitch> simple_switch = std::make_shared<SimpleSwitch>(!disable_swap_flag, drop_port);

#ifdef WITH_THRIFT
  int thrift_port = simple_switch->get_runtime_port();
  bm_runtime::start_server(simple_switch.get(), thrift_port);
  using ::sswitch_runtime::SimpleSwitchIf;
  using ::sswitch_runtime::SimpleSwitchProcessor;
  bm_runtime::add_service<SimpleSwitchIf, SimpleSwitchProcessor>(
          "simple_switch", sswitch_runtime::get_handler(simple_switch.get()));
#else
  if (parser.option_was_provided("thrift-port")) {
    bm::Logger::get()->warn(
        "You used the '--thrift-port' command-line option, but this target was "
        "compiled without Thrift support. You can enable Thrift support (not "
        "recommended) by providing '--with-thrift' to configure.");
  }
#endif  // WITH_THRIFT

#ifdef WITH_SYSREPO
  sysrepo_driver = std::unique_ptr<SysrepoDriver>(new SysrepoDriver(
      parser.device_id, switch_target.get()));

  if (!sysrepo_driver->start()) return 1;
  for (const auto &p : saved_interfaces)
    sysrepo_driver->add_iface(p.first, p.second);
#endif  // WITH_SYSREPO

  auto &runner = switch_runner::SwitchGrpcRunner::get_instance(
      simple_switch,
      grpc_server_addr,
      cpu_port,
      dp_grpc_server_addr,
      grpc_server_ssl ? ssl_options : nullptr,
      priority_queues);
  int status = runner.init_and_start(parser);
  if (status != 0) std::exit(status);

  runner.wait();
  return 0;
}
