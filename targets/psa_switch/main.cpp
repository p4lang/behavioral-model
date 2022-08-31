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


/* Switch instance */

#include <iostream>

#include <bm/PsaSwitch.h>
#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/target_parser.h>

#ifdef WITH_PI
#include <bm/bm_grpc/pem.h>
#include <bm/grpc/ssl_options.h>
#endif

#include "psa_switch.h"

namespace {
bm::psa::PsaSwitch *psa_switch;
bm::TargetParserBasic *psa_switch_parser;
}  // namespace

namespace pswitch_runtime {
shared_ptr<PsaSwitchIf> get_handler(bm::psa::PsaSwitch *sw);
}  // namespace pswitch_runtime

int
main(int argc, char* argv[]) {
  using bm::psa::PsaSwitch;
  psa_switch = new PsaSwitch();
  psa_switch_parser = new bm::TargetParserBasic();
  psa_switch_parser->add_flag_option(
    "enable-swap",
    "enable JSON swapping at runtime"
  );
  psa_switch_parser->add_uint_option(
    "drop-port",
    "Choose a numerical value for the drop port (default is 511). "
    "You will need to use this command-line option when you wish to use port "
    "511 as a valid dataplane port or as the CPU port."
  );
  psa_switch_parser->add_uint_option(
    "cpu-port",
    "Choose a numerical value for the CPU port, it will be used for "
    "packet-in / packet-out. Do not add an interface with this port number, "
    "and 0 is not a valid value. "
    "If you do not use this command-line option, "
    "P4Runtime packet IO functionality will not be available: you will not "
    "be able to receive / send packets using the P4Runtime StreamChannel "
    "bi-directional stream."
  );

#ifdef WITH_PI
  psa_switch_parser->add_string_option(
    "grpc-server-addr",
    "Bind gRPC server to given address [default is 0.0.0.0:9559]"
  );
  psa_switch_parser->add_flag_option(
    "grpc-server-ssl",
    "Enable SSL/TLS for gRPC server"
  );
  psa_switch_parser->add_string_option(
    "grpc-server-cacert",
    "Path to pem file holding CA certificate to verify peer against"
  );
  psa_switch_parser->add_string_option(
    "grpc-server-cert",
    "Path to pem file holding server certificate"
  );
  psa_switch_parser->add_string_option(
    "grpc-server-key",
    "Path to pem file holding server key"
  );
  psa_switch_parser->add_flag_option(
    "grpc-server-with-client-auth",
    "Require client to have a valid certificate for mutual authentication"
  );
  psa_switch_parser->add_flag_option(
    "dp-grpc-server-addr",
    "Use a gRPC channel to inject and receive dataplane packets; "
      "bind this gRPC server to given address, e.g. 0.0.0.0:50052"
  );
#endif  // WITH_PI

  int status = psa_switch->init_from_command_line_options(
      argc, argv, psa_switch_parser);
  if (status != 0) {
    std::cerr << "Failed to initialize switch from command-line options\n";
    std::exit(status);
  }

  bool enable_swap_flag = false;
  if (psa_switch_parser->get_flag_option("enable-swap", &enable_swap_flag)
      != bm::TargetParserBasic::ReturnCode::SUCCESS) {
    std::cerr << "Failed to get enable-swap value\n";
    std::exit(1);
  }
  if (enable_swap_flag) psa_switch->enable_config_swap();

  uint32_t drop_port = 0xffffffff;
  {
    auto rc = psa_switch_parser->get_uint_option("drop-port", &drop_port);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      drop_port = PsaSwitch::default_drop_port;
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS) {
      std::cerr << "Failed to get drop-port value\n";
      std::exit(1);
    }
    psa_switch->set_drop_port(drop_port);
  }

  uint32_t cpu_port = 0xffffffff;
  {
    auto rc = psa_switch_parser->get_uint_option("cpu-port", &cpu_port);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      cpu_port = 0;
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS || cpu_port == 0) {
      std::cerr << "Failed to get cpu-port value\n";
      std::exit(1);
    }
  }

#ifdef WITH_PI
  std::string dp_grpc_server_addr;
  {
    auto rc = psa_switch_parser->get_string_option(
        "dp-grpc-server-addr", &dp_grpc_server_addr);
    if (rc != bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED &&
        rc != bm::TargetParserBasic::ReturnCode::SUCCESS) {
      std::cerr << "Failed to get dp-grpc-server-addr value\n";
      std::exit(1);
    }
  }

  std::string grpc_server_addr;
  {
    auto rc = psa_switch_parser->get_string_option(
        "grpc-server-addr", &grpc_server_addr);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      grpc_server_addr = "0.0.0.0:9559";
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS) {
      std::cerr << "Failed to get grpc-server-addr value\n";
      std::exit(1);
    }
  }

  bool grpc_server_ssl = false;
  {
    auto rc = psa_switch_parser->get_flag_option(
        "grpc-server-ssl", &grpc_server_ssl);
    if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS) {
      std::cerr << "Failed to get grpc-server-ssl value\n";
      std::exit(1);
    }
  }

  std::string grpc_server_cacert;
  {
    auto rc = psa_switch_parser->get_string_option(
        "grpc-server-cacert", &grpc_server_cacert);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      grpc_server_cacert = "";
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS) {
      std::cerr << "Failed to get grpc-server-cacert value\n";
      std::exit(1);
    }
  }

  std::string grpc_server_cert;
  {
    auto rc = psa_switch_parser->get_string_option(
        "grpc-server-cert", &grpc_server_cert);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      grpc_server_cert = "";
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS) {
      std::cerr << "Failed to get grpc-server-cert value\n";
      std::exit(1);
    }
  }

  std::string grpc_server_key;
  {
    auto rc = psa_switch_parser->get_string_option(
        "grpc-server-key", &grpc_server_key);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      grpc_server_key = "";
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS) {
      std::cerr << "Failed to get grpc-server-key value\n";
      std::exit(1);
    }
  }

  bool grpc_server_with_client_auth = false;
  {
    auto rc = psa_switch_parser->get_flag_option(
        "grpc-server-with-client-auth", &grpc_server_with_client_auth);
    if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS) {
      std::cerr << "Failed to get grpc-server-with-client-auth value\n";
      std::exit(1);
    }
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
#endif  // WITH_PI

  int thrift_port = psa_switch->get_runtime_port();
  bm_runtime::start_server(psa_switch, thrift_port);
  using ::pswitch_runtime::PsaSwitchIf;
  using ::pswitch_runtime::PsaSwitchProcessor;
  bm_runtime::add_service<PsaSwitchIf, PsaSwitchProcessor>(
      "psa_switch", pswitch_runtime::get_handler(psa_switch));
  psa_switch->start_and_return();

  while (true) std::this_thread::sleep_for(std::chrono::seconds(100));

  return 0;
}
