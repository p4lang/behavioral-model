/* Copyright 2018-present Barefoot Networks, Inc.
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

#ifndef PI_SRC_PI_TABLE_INT_H_
#define PI_SRC_PI_TABLE_INT_H_

#include "PI/pi_base.h"

#ifdef __cplusplus
extern "C" {
#endif

pi_status_t pi_table_init();

pi_status_t pi_table_destroy();

pi_status_t pi_table_assign_device(pi_dev_id_t dev_id);

pi_status_t pi_table_remove_device(pi_dev_id_t dev_id);

#ifdef __cplusplus
}
#endif

#endif  // PI_SRC_PI_TABLE_INT_H_
