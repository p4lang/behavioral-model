// Copyright 2024 Marvell Technology, Inc.
// SPDX-FileCopyrightText: 2024 Marvell Technology, Inc.
//
// SPDX-License-Identifier: Apache-2.0
 
/*
 * Rupesh Chiluka (rchiluka@marvell.com)
 *
 */

/* Nic instance */

#include <bm/PnaNic.h>
#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/target_parser.h>

#include "pna_nic.h"

namespace {
bm::pna::PnaNic *pna_nic;
bm::TargetParserBasic *pna_nic_parser;
}  // namespace

namespace pnic_runtime {
shared_ptr<PnaNicIf> get_handler(bm::pna::PnaNic *nic);
}  // namespace pnic_runtime

int
main(int argc, char* argv[]) {
  using bm::pna::PnaNic;
  pna_nic = new PnaNic();
  pna_nic_parser = new bm::TargetParserBasic();
  pna_nic_parser->add_flag_option("enable-swap",
                                        "enable JSON swapping at runtime");
  int status = pna_nic->init_from_command_line_options(
      argc, argv, pna_nic_parser);
  if (status != 0) std::exit(status);

  bool enable_swap_flag = false;
  if (pna_nic_parser->get_flag_option("enable-swap", &enable_swap_flag)
      != bm::TargetParserBasic::ReturnCode::SUCCESS)
    std::exit(1);
  if (enable_swap_flag) pna_nic->enable_config_swap();

  int thrift_port = pna_nic->get_runtime_port();
  bm_runtime::start_server(pna_nic, thrift_port);
  using ::pnic_runtime::PnaNicIf;
  using ::pnic_runtime::PnaNicProcessor;
  bm_runtime::add_service<PnaNicIf, PnaNicProcessor>(
      "pna_nic", pnic_runtime::get_handler(pna_nic));
  pna_nic->start_and_return();

  while (true) std::this_thread::sleep_for(std::chrono::seconds(100));

  return 0;
}
