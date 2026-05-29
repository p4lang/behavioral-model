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

#ifndef BM_BM_SIM_DEVICE_ID_H_
#define BM_BM_SIM_DEVICE_ID_H_

#include <cstdint>
#include <utility>

namespace bm {

// s_* for serialized value format (e.g. notifications)
using device_id_t = uint64_t;
using s_device_id_t = device_id_t;
using cxt_id_t = uint32_t;
using s_cxt_id_t = cxt_id_t;

}  // namespace bm

#endif  // BM_BM_SIM_DEVICE_ID_H_
