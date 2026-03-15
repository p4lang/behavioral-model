/* Copyright 2013-present Barefoot Networks, Inc.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef PI_TOOLKIT__ASSERT_H_
#define PI_TOOLKIT__ASSERT_H_

#ifdef __cplusplus
extern "C" {
#endif

// An assert that cannot be removed with NDEBUG

// TODO(antonin): is this portable?
#define _PI_NORETURN __attribute__((noreturn))

_PI_NORETURN void _pi_assert(const char* expr, const char* file, int line);

#define _PI_ASSERT(expr) \
  ((expr) ? (void)0 : _pi_assert(#expr, __FILE__, __LINE__))

#define _PI_UNREACHABLE(msg) _pi_assert(msg, __FILE__, __LINE__)

#define _PI_UNUSED(x) ((void)x)

#ifdef __cplusplus
}
#endif

#endif  // PI_TOOLKIT__ASSERT_H_
