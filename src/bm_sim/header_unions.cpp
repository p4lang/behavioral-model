// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/headers.h>
#include <bm/bm_sim/header_unions.h>

namespace bm {

bool
HeaderUnion::cmp(const HeaderUnion &other) const {
  return valid && other.valid &&
      (valid_header_idx == other.valid_header_idx) &&
      headers[valid_header_idx].get().cmp(other.headers[valid_header_idx]);
}

}  // namespace bm
