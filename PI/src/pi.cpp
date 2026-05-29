// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/PI/pi.h>

#include "common.h"

namespace pibmv2 {

bm::SwitchWContexts *switch_ = nullptr;

uint32_t cpu_port = 0;

}  // namespace pibmv2

namespace bm {

namespace pi {

void register_switch(bm::SwitchWContexts *sw, uint32_t cpu_port) {
  ::pibmv2::switch_ = sw;
  ::pibmv2::cpu_port = cpu_port;
}

}  // namespace pi

}  // namespace bm
