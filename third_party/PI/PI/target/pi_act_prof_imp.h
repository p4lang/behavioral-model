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

#ifndef PI_INC_PI_TARGET_PI_ACT_PROF_IMP_H_
#define PI_INC_PI_TARGET_PI_ACT_PROF_IMP_H_

#include <PI/pi_act_prof.h>

#ifdef __cplusplus
extern "C" {
#endif

pi_status_t _pi_act_prof_mbr_create(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id,
                                    const pi_action_data_t *action_data,
                                    pi_indirect_handle_t *mbr_handle);

pi_status_t _pi_act_prof_mbr_delete(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle);

pi_status_t _pi_act_prof_mbr_modify(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle,
                                    const pi_action_data_t *action_data);

pi_status_t _pi_act_prof_grp_create(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id, size_t max_size,
                                    pi_indirect_handle_t *grp_handle);

pi_status_t _pi_act_prof_grp_delete(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t grp_handle);

pi_status_t _pi_act_prof_grp_add_mbr(pi_session_handle_t session_handle,
                                     pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                     pi_indirect_handle_t grp_handle,
                                     pi_indirect_handle_t mbr_handle);

pi_status_t _pi_act_prof_grp_remove_mbr(pi_session_handle_t session_handle,
                                        pi_dev_id_t dev_id,
                                        pi_p4_id_t act_prof_id,
                                        pi_indirect_handle_t grp_handle,
                                        pi_indirect_handle_t mbr_handle);

pi_status_t _pi_act_prof_grp_set_mbrs(
    pi_session_handle_t session_handle, pi_dev_id_t dev_id,
    pi_p4_id_t act_prof_id, pi_indirect_handle_t grp_handle, size_t num_mbrs,
    const pi_indirect_handle_t *mbr_handles, const bool *activate);

pi_status_t _pi_act_prof_grp_activate_mbr(pi_session_handle_t session_handle,
                                          pi_dev_id_t dev_id,
                                          pi_p4_id_t act_prof_id,
                                          pi_indirect_handle_t grp_handle,
                                          pi_indirect_handle_t mbr_handle);

pi_status_t _pi_act_prof_grp_deactivate_mbr(pi_session_handle_t session_handle,
                                            pi_dev_id_t dev_id,
                                            pi_p4_id_t act_prof_id,
                                            pi_indirect_handle_t grp_handle,
                                            pi_indirect_handle_t mbr_handle);

pi_status_t _pi_act_prof_entries_fetch(pi_session_handle_t session_handle,
                                       pi_dev_tgt_t dev_tgt,
                                       pi_p4_id_t act_prof_id,
                                       pi_act_prof_fetch_res_t *res);

pi_status_t _pi_act_prof_mbr_fetch(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t mbr_handle,
                                   pi_act_prof_fetch_res_t *res);

pi_status_t _pi_act_prof_grp_fetch(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t grp_handle,
                                   pi_act_prof_fetch_res_t *res);

pi_status_t _pi_act_prof_entries_fetch_done(pi_session_handle_t session_handle,
                                            pi_act_prof_fetch_res_t *res);

int _pi_act_prof_api_support(pi_dev_id_t dev_id);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_TARGET_PI_ACT_PROF_IMP_H_
