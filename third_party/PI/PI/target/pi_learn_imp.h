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

#ifndef PI_INC_PI_TARGET_PI_LEARN_IMP_H_
#define PI_INC_PI_TARGET_PI_LEARN_IMP_H_

#include <PI/pi_learn.h>

#ifdef __cplusplus
extern "C" {
#endif

pi_status_t pi_learn_new_msg(pi_learn_msg_t *msg);

pi_status_t _pi_learn_config_set(pi_session_handle_t session_handle,
                                 pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                                 const pi_learn_config_t *config);

pi_status_t _pi_learn_msg_ack(pi_session_handle_t session_handle,
                              pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                              pi_learn_msg_id_t msg_id);

pi_status_t _pi_learn_msg_done(pi_learn_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_TARGET_PI_LEARN_IMP_H_
