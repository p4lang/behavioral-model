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

// TODO: temporary placeholder

#ifndef PI_SRC_UTILS_LOGGING_H_
#define PI_SRC_UTILS_LOGGING_H_

#include <stdio.h>

extern int _logs_on;

void pi_logs_on();
void pi_logs_off();

#ifdef PI_LOG_ON
#define PI_LOG_DEBUG(...) \
  if (_logs_on) fprintf(stderr, __VA_ARGS__)
#define PI_LOG_ERROR(...) \
  if (_logs_on) fprintf(stderr, __VA_ARGS__)
#else
#define PI_LOG_DEBUG(...)
#define PI_LOG_ERROR(...)
#endif

#endif  // PI_SRC_UTILS_LOGGING_H_
