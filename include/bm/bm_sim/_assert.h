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

#ifndef BM_BM_SIM__ASSERT_H_
#define BM_BM_SIM__ASSERT_H_

// An assert that cannot be removed with NDEBUG

namespace bm {

[[ noreturn ]] void _bm_assert(const char* expr, const char* file, int line);

}  // namespace bm

#define _BM_ASSERT(expr) \
  ((expr) ? (void)0 : bm::_bm_assert(#expr, __FILE__, __LINE__))

#define _BM_UNREACHABLE(msg) bm::_bm_assert(msg, __FILE__, __LINE__)

#define _BM_UNUSED(x) ((void)x)

#endif  // BM_BM_SIM__ASSERT_H_
