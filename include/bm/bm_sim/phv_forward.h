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

#ifndef BM_BM_SIM_PHV_FORWARD_H_
#define BM_BM_SIM_PHV_FORWARD_H_

namespace bm {

using header_id_t = int;
using header_stack_id_t = int;
using header_union_id_t = int;
using header_union_stack_id_t = int;

class PHV;
class PHVFactory;
class Header;
class Field;

}  // namespace bm

#endif  // BM_BM_SIM_PHV_FORWARD_H_
