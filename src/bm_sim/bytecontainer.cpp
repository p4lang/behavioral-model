// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/bytecontainer.h>

#include <string>
#include <sstream>

#include "utils.h"

namespace bm {

std::string
ByteContainer::to_hex(size_t start, size_t s, bool upper_case) const {
  assert(start + s <= size());

  std::ostringstream ret;
  // in debug mode, some compilers perform bound-checking even for operator[]
  // utils::dump_hexstring(ret, &bytes[start], &bytes[start + s], upper_case);
  auto first = bytes.begin() + start;
  utils::dump_hexstring(ret, first, first + s, upper_case);
  return ret.str();
}

}  // namespace bm
