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

#include <bm/PortableSwitch.h>
#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/target_parser.h>

#include "portable_switch.h"

namespace {
PortableSwitch *portable_switch;
bm::TargetParserBasic *portable_switch_parser;
}  // namespace

namespace pswitch_runtime {
shared_ptr<PortableSwitchIf> get_handler(PortableSwitch *sw);
}  // namespace pswitch_runtime

int
main(int argc, char* argv[]) {
  portable_switch = new PortableSwitch();
  portable_switch_parser = new bm::TargetParserBasic();
  portable_switch_parser->add_flag_option("enable-swap",
                                        "enable JSON swapping at runtime");
  int status = portable_switch->init_from_command_line_options(
      argc, argv, portable_switch_parser);
  if (status != 0) std::exit(status);

  bool enable_swap_flag = false;
  if (portable_switch_parser->get_flag_option("enable-swap", &enable_swap_flag)
      != bm::TargetParserBasic::ReturnCode::SUCCESS)
    std::exit(1);
  if (enable_swap_flag) portable_switch->enable_config_swap();

  int thrift_port = portable_switch->get_runtime_port();
  bm_runtime::start_server(portable_switch, thrift_port);
  using ::pswitch_runtime::PortableSwitchIf;
  using ::pswitch_runtime::PortableSwitchProcessor;
  bm_runtime::add_service<PortableSwitchIf, PortableSwitchProcessor>(
      "portable_switch", pswitch_runtime::get_handler(portable_switch));
  portable_switch->start_and_return();

  while (true) std::this_thread::sleep_for(std::chrono::seconds(100));

  return 0;
}
