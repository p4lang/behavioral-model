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

#include <PI/pi.h>
#include <PI/pi_counter.h>
#include <PI/target/pi_counter_imp.h>

static bool is_direct_counter(const pi_p4info_t *p4info,
                              pi_p4_id_t counter_id) {
  return (pi_p4info_counter_get_direct(p4info, counter_id) != PI_INVALID_ID);
}

pi_status_t pi_counter_read(pi_session_handle_t session_handle,
                            pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                            size_t index, int flags,
                            pi_counter_data_t *counter_data) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (is_direct_counter(p4info, counter_id)) return PI_STATUS_COUNTER_IS_DIRECT;
  return _pi_counter_read(session_handle, dev_tgt, counter_id, index, flags,
                          counter_data);
}

pi_status_t pi_counter_write(pi_session_handle_t session_handle,
                             pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                             size_t index,
                             const pi_counter_data_t *counter_data) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (is_direct_counter(p4info, counter_id)) return PI_STATUS_COUNTER_IS_DIRECT;
  return _pi_counter_write(session_handle, dev_tgt, counter_id, index,
                           counter_data);
}

pi_status_t pi_counter_read_direct(pi_session_handle_t session_handle,
                                   pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                   pi_entry_handle_t entry_handle, int flags,
                                   pi_counter_data_t *counter_data) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (!is_direct_counter(p4info, counter_id))
    return PI_STATUS_COUNTER_IS_NOT_DIRECT;
  return _pi_counter_read_direct(session_handle, dev_tgt, counter_id,
                                 entry_handle, flags, counter_data);
}

pi_status_t pi_counter_write_direct(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                    pi_entry_handle_t entry_handle,
                                    const pi_counter_data_t *counter_data) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (!is_direct_counter(p4info, counter_id))
    return PI_STATUS_COUNTER_IS_NOT_DIRECT;
  return _pi_counter_write_direct(session_handle, dev_tgt, counter_id,
                                  entry_handle, counter_data);
}

pi_status_t pi_counter_hw_sync(pi_session_handle_t session_handle,
                               pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                               PICounterHwSyncCb cb, void *cb_cookie) {
  return _pi_counter_hw_sync(session_handle, dev_tgt, counter_id, cb,
                             cb_cookie);
}
