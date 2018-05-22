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

#include <dlfcn.h>
#include <bm/SimpleSwitch.h>
#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/target_parser.h>

#include <sstream>
#include <string>
#include <vector>

#include "simple_switch.h"

namespace {
SimpleSwitch *simple_switch;

std::string load_modules_option = "load-modules";

class TargetParserModules : public bm::TargetParserBasic {
 public:
  TargetParserModules() {
    add_flag_option("enable-swap",
                    "enable JSON swapping at runtime");
  }

  int parse(const std::vector<std::string> &more_options,
                    std::ostream *errstream) override {
    int result = ::bm::TargetParserBasic::parse(more_options, errstream);
    set_enable_swap();
    return result;
  }

 protected:
  void set_enable_swap() {
    bool enable_swap = false;
    if (get_flag_option("enable-swap", &enable_swap) != ReturnCode::SUCCESS)
      std::exit(1);
    if (enable_swap) simple_switch->enable_config_swap();
  }
};

TargetParserModules *simple_switch_parser;
}  // namespace

namespace sswitch_runtime {
shared_ptr<SimpleSwitchIf> get_handler(SimpleSwitch *sw);
}  // namespace sswitch_runtime

int
main(int argc, char* argv[]) {
  simple_switch = new SimpleSwitch();
  simple_switch_parser = new TargetParserModules();
  int status = simple_switch->init_from_command_line_options(
      argc, argv, simple_switch_parser);
  if (status != 0) std::exit(status);

  int thrift_port = simple_switch->get_runtime_port();
  bm_runtime::start_server(simple_switch, thrift_port);
  using ::sswitch_runtime::SimpleSwitchIf;
  using ::sswitch_runtime::SimpleSwitchProcessor;
  bm_runtime::add_service<SimpleSwitchIf, SimpleSwitchProcessor>(
      "simple_switch", sswitch_runtime::get_handler(simple_switch));
  simple_switch->start_and_return();

  while (true) std::this_thread::sleep_for(std::chrono::seconds(100));

  return 0;
}
