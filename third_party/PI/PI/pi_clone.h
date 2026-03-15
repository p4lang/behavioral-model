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

//! @file

#ifndef PI_INC_PI_PI_CLONE_H_
#define PI_INC_PI_PI_CLONE_H_

#include <PI/pi_base.h>
#include <PI/pi_mc.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t pi_clone_session_id_t;
typedef int32_t pi_clone_port_t;

typedef enum {
  PI_CLONE_DIRECTION_NONE = 0,
  PI_CLONE_DIRECTION_I2E,
  PI_CLONE_DIRECTION_E2E,
  PI_CLONE_DIRECTION_BOTH,
} pi_clone_direction_t;

typedef struct {
  pi_clone_direction_t direction;
  pi_port_t eg_port;
  bool eg_port_valid;
  pi_mc_grp_id_t mc_grp_id;
  bool mc_grp_id_valid;
  bool copy_to_cpu;
  uint16_t max_packet_length;  // 0 means no truncation
  uint32_t cos;
} pi_clone_session_config_t;

//! Enables a cloning session. Is allowed to fail if multicast group does not
//! exist (we leave it up to the target).
pi_status_t pi_clone_session_set(
    pi_session_handle_t session_handle, pi_dev_tgt_t dev_tgt,
    pi_clone_session_id_t clone_session_id,
    const pi_clone_session_config_t *clone_session_config);

//! Resets state for a clone session. We exect this to succeed even if the
//! session does not "exist", i.e. was not previously set.
pi_status_t pi_clone_session_reset(pi_session_handle_t session_handle,
                                   pi_dev_tgt_t dev_tgt,
                                   pi_clone_session_id_t clone_session_id);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_CLONE_H_
