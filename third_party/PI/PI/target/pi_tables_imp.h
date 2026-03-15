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

#ifndef PI_INC_PI_TARGET_PI_TABLES_IMP_H_
#define PI_INC_PI_TARGET_PI_TABLES_IMP_H_

#include <PI/pi_tables.h>

#ifdef __cplusplus
extern "C" {
#endif

pi_status_t _pi_table_entry_add(pi_session_handle_t session_handle,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t table_id,
                                const pi_match_key_t *match_key,
                                const pi_table_entry_t *table_entry,
                                int overwrite, pi_entry_handle_t *entry_handle);

pi_status_t _pi_table_default_action_set(pi_session_handle_t session_handle,
                                         pi_dev_tgt_t dev_tgt,
                                         pi_p4_id_t table_id,
                                         const pi_table_entry_t *table_entry);

pi_status_t _pi_table_default_action_reset(pi_session_handle_t session_handle,
                                           pi_dev_tgt_t dev_tgt,
                                           pi_p4_id_t table_id);

pi_status_t _pi_table_default_action_get(pi_session_handle_t session_handle,
                                         pi_dev_tgt_t dev_id,
                                         pi_p4_id_t table_id,
                                         pi_table_entry_t *table_entry);

pi_status_t _pi_table_default_action_done(pi_session_handle_t session_handle,
                                          pi_table_entry_t *table_entry);

pi_status_t _pi_table_default_action_get_handle(
    pi_session_handle_t session_handle, pi_dev_tgt_t dev_tgt,
    pi_p4_id_t table_id, pi_entry_handle_t *entry_handle);

pi_status_t _pi_table_entry_delete(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                   pi_entry_handle_t entry_handle);

pi_status_t _pi_table_entry_delete_wkey(pi_session_handle_t session_handle,
                                        pi_dev_tgt_t dev_tgt,
                                        pi_p4_id_t table_id,
                                        const pi_match_key_t *match_key);

pi_status_t _pi_table_entry_modify(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                   pi_entry_handle_t entry_handle,
                                   const pi_table_entry_t *table_entry);

pi_status_t _pi_table_entry_modify_wkey(pi_session_handle_t session_handle,
                                        pi_dev_tgt_t dev_tgt,
                                        pi_p4_id_t table_id,
                                        const pi_match_key_t *match_key,
                                        const pi_table_entry_t *table_entry);

pi_status_t _pi_table_entries_fetch(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt, pi_p4_id_t table_id,
                                    pi_table_fetch_res_t *res);

pi_status_t _pi_table_entries_fetch_one(pi_session_handle_t session_handle,
                                        pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                        pi_entry_handle_t entry_handle,
                                        pi_table_fetch_res_t *res);

pi_status_t _pi_table_entries_fetch_wkey(pi_session_handle_t session_handle,
                                         pi_dev_tgt_t dev_tgt,
                                         pi_p4_id_t table_id,
                                         const pi_match_key_t *match_key,
                                         pi_table_fetch_res_t *res);

pi_status_t _pi_table_entries_fetch_done(pi_session_handle_t session_handle,
                                         pi_table_fetch_res_t *res);

pi_status_t _pi_table_idle_timeout_config_set(
    pi_session_handle_t session_handle, pi_dev_id_t dev_id, pi_p4_id_t table_id,
    const pi_idle_timeout_config_t *config);

pi_status_t _pi_table_entry_get_remaining_ttl(
    pi_session_handle_t session_handle, pi_dev_id_t dev_id, pi_p4_id_t table_id,
    pi_entry_handle_t entry_handle, uint64_t *ttl_ns);

//! To be called by target to notify application when an entry's TLL expires.
//! Target owns the memory for match_key and can free it after the function
//! returns.
//! match_key pointer is not const because PI code needs to set
//! match_key->p4info before calling the application's callback.
pi_status_t pi_table_idle_timeout_notify(pi_dev_id_t dev_id,
                                         pi_p4_id_t table_id,
                                         pi_match_key_t *match_key,
                                         pi_entry_handle_t entry_handle);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_TARGET_PI_TABLES_IMP_H_
