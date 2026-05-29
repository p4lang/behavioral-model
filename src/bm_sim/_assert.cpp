// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/_assert.h>

#include <cstdlib>
#include <iostream>

namespace bm {

void _bm_assert(const char* expr, const char* file, int line) {
  std::cerr << "Assertion '" << expr << "' failed, file '" << file
            << "' line '" << line << "'.\n";
  std::abort();
}

}  // namespace bm
