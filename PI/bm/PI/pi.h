/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef BM_PI_PI_H_
#define BM_PI_PI_H_

#include <PI/pi.h>

#include <cstdint>

namespace bm {

class SwitchWContexts;  // forward declaration

namespace pi {

void register_switch(bm::SwitchWContexts *sw, uint32_t cpu_port = 0);

pi_status_t table_idle_timeout_notify(pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                      pi_entry_handle_t entry_handle);

}  // namespace pi

}  // namespace bm

#endif  // BM_PI_PI_H_
