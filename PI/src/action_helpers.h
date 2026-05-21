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

#ifndef SRC_ACTION_HELPERS_H_
#define SRC_ACTION_HELPERS_H_

#include <bm/bm_sim/actions.h>

#include <PI/pi.h>

#include <string>
#include <vector>

namespace pibmv2 {

bm::ActionData build_action_data(const pi_action_data_t *action_data,
                                 const pi_p4info_t *p4info);

char *dump_action_data(const pi_p4info_t *p4info, char *data,
                       pi_p4_id_t action_id, const bm::ActionData &action_data);

}  // namespace pibmv2

#endif  // SRC_ACTION_HELPERS_H_
