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

//! @file

#ifndef PI_INC_PI_PI_LEARN_H_
#define PI_INC_PI_PI_LEARN_H_

#include "pi_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t pi_learn_msg_id_t;

typedef struct {
  int32_t max_size;
  int64_t max_timeout_ns;
} pi_learn_config_t;

//! A learn message.
typedef struct {
  pi_dev_tgt_t dev_tgt;
  pi_p4_id_t learn_id;
  pi_learn_msg_id_t msg_id;
  size_t num_entries;
  size_t entry_size;  // can be inferred from learn_id but easier to have here
  char *entries;
} pi_learn_msg_t;

//! Callback type for learn events.
typedef void (*PILearnCb)(pi_learn_msg_t *msg, void *cb_cookie);

// no session_handle for these APIs, do they need one?
// because none of these calls result to a backend driver call, I do not see why
// they would

//! Register a learn callback for a given device
pi_status_t pi_learn_register_cb(pi_dev_id_t dev_id, PILearnCb cb,
                                 void *cb_cookie);

//! Default callback. Will be called if no callback registered for a given
//! device.
pi_status_t pi_learn_register_default_cb(PILearnCb cb, void *cb_cookie);

//! De-register callback for given device.
pi_status_t pi_learn_deregister_cb(pi_dev_id_t dev_id);

//! De-register default callback.
pi_status_t pi_learn_deregister_default_cb();

//! Configure learning
//! Learning disabled by default for digest
//! A nullptr for config disables learning
pi_status_t pi_learn_config_set(pi_session_handle_t session_handle,
                                pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                                const pi_learn_config_t *config);

//! Ack a received learn message. This indicates to the target that you have
//! fully processed the message and that it can remove the message from its
//! duplicate filter (for example).
pi_status_t pi_learn_msg_ack(pi_session_handle_t session_handle,
                             pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                             pi_learn_msg_id_t msg_id);

//! Indicate that you are done with the learn message and that any associated
//! memory can be released.
pi_status_t pi_learn_msg_done(pi_learn_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_LEARN_H_
