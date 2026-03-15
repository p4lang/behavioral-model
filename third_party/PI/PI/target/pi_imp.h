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

#ifndef PI_INC_PI_TARGET_PI_IMP_H_
#define PI_INC_PI_TARGET_PI_IMP_H_

#include "PI/pi.h"

#ifdef __cplusplus
extern "C" {
#endif

pi_status_t _pi_init(int *abi_version, void *extra);

pi_status_t _pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                              pi_assign_extra_t *extra);

pi_status_t _pi_update_device_start(pi_dev_id_t dev_id,
                                    const pi_p4info_t *p4info,
                                    const char *device_data,
                                    size_t device_data_size);

pi_status_t _pi_update_device_end(pi_dev_id_t dev_id);

pi_status_t _pi_remove_device(pi_dev_id_t dev_id);

pi_status_t _pi_session_init(pi_session_handle_t *session_handle);

pi_status_t _pi_session_cleanup(pi_session_handle_t session_handle);

pi_status_t _pi_batch_begin(pi_session_handle_t session_handle);

pi_status_t _pi_batch_end(pi_session_handle_t session_handle, bool hw_sync);

pi_status_t _pi_destroy();

pi_status_t _pi_packetout_send(pi_dev_id_t dev_id, const char *pkt,
                               size_t size);

pi_status_t _pi_port_status_get(pi_dev_id_t dev_id, pi_port_t port,
                                pi_port_status_t *status);

pi_status_t pi_packetin_receive(pi_dev_id_t dev_id, const char *pkt,
                                size_t size);

pi_status_t pi_port_status_event_notify(pi_dev_id_t dev_id, pi_port_t port,
                                        pi_port_status_t status);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_TARGET_PI_IMP_H_
