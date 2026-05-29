// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

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
  psa_switch_parser->add_flag_option("enable-swap",
                                        "enable JSON swapping at runtime");
  int status = psa_switch->init_from_command_line_options(
      argc, argv, psa_switch_parser);
  if (status != 0) std::exit(status);

  bool enable_swap_flag = false;
  if (psa_switch_parser->get_flag_option("enable-swap", &enable_swap_flag)
      != bm::TargetParserBasic::ReturnCode::SUCCESS)
    std::exit(1);
  if (enable_swap_flag) psa_switch->enable_config_swap();

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
