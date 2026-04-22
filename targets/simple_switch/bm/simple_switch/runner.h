/*
 * SPDX-FileCopyrightText: 2018 Barefoot Networks, Inc.
 * Copyright 2018-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef SIMPLE_SWITCH_BM_SIMPLE_SWITCH_RUNNER_H_
#define SIMPLE_SWITCH_BM_SIMPLE_SWITCH_RUNNER_H_

#include <bm/bm_sim/dev_mgr.h>
#include <bm/bm_sim/device_id.h>
#include <bm/bm_sim/options_parse.h>

#include <cstdint>
#include <memory>

class SimpleSwitch;

namespace bm {

namespace sswitch {

class SimpleSwitchRunner {
 public:
  static constexpr uint32_t default_drop_port = 511;

  explicit SimpleSwitchRunner(uint32_t cpu_port = 0,
                              uint32_t drop_port = default_drop_port);
  ~SimpleSwitchRunner();

  int init_and_start(const bm::OptionsParser &parser);

  device_id_t get_device_id() const;

  DevMgr *get_dev_mgr();

 private:
  uint32_t cpu_port{0};
  std::unique_ptr<SimpleSwitch> simple_switch;
};

}  // namespace sswitch

}  // namespace bm

#endif  // SIMPLE_SWITCH_BM_SIMPLE_SWITCH_RUNNER_H_
