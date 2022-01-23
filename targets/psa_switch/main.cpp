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

#include <bm/PsaSwitch.h>
#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/target_parser.h>

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

  int status = psa_switch->init_from_command_line_options(
      argc, argv, psa_switch_parser);
  if (status != 0) std::exit(status);

  bool enable_swap_flag = false;
  if (psa_switch_parser->get_flag_option("enable-swap", &enable_swap_flag)
      != bm::TargetParserBasic::ReturnCode::SUCCESS)
    std::exit(1);
  if (enable_swap_flag) psa_switch->enable_config_swap();

  uint32_t drop_port = 0xffffffff;
  {
    auto rc = psa_switch_parser->get_uint_option("drop-port", &drop_port);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      drop_port = PsaSwitch::default_drop_port;
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
    psa_switch->set_drop_port(drop_port);
  }

  uint32_t cpu_port = 0xffffffff;
  {
    auto rc = psa_switch_parser->get_uint_option("cpu-port", &cpu_port);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      cpu_port = 0;
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS || cpu_port == 0)
      std::exit(1);
  }

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
