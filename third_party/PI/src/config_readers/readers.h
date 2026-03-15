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

#ifndef PI_SRC_CONFIG_READERS_READERS_H_
#define PI_SRC_CONFIG_READERS_READERS_H_

#include "PI/pi_base.h"

pi_status_t pi_bmv2_json_reader(const char *config, pi_p4info_t *p4info);

pi_status_t pi_native_json_reader(const char *config, pi_p4info_t *p4info);

#endif  // PI_SRC_CONFIG_READERS_READERS_H_
