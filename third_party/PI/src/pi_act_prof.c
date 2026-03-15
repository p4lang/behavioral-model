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

#include <PI/int/pi_int.h>
#include <PI/int/serialize.h>
#include <PI/pi_tables.h>
#include <PI/target/pi_act_prof_imp.h>

#include <stdlib.h>

pi_status_t pi_act_prof_mbr_create(pi_session_handle_t session_handle,
                                   pi_dev_tgt_t dev_tgt, pi_p4_id_t act_prof_id,
                                   const pi_action_data_t *action_data,
                                   pi_indirect_handle_t *mbr_handle) {
  return _pi_act_prof_mbr_create(session_handle, dev_tgt, act_prof_id,
                                 action_data, mbr_handle);
}

pi_status_t pi_act_prof_mbr_delete(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t mbr_handle) {
  return _pi_act_prof_mbr_delete(session_handle, dev_id, act_prof_id,
                                 mbr_handle);
}

pi_status_t pi_act_prof_mbr_modify(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t mbr_handle,
                                   const pi_action_data_t *action_data) {
  return _pi_act_prof_mbr_modify(session_handle, dev_id, act_prof_id,
                                 mbr_handle, action_data);
}

pi_status_t pi_act_prof_grp_create(pi_session_handle_t session_handle,
                                   pi_dev_tgt_t dev_tgt, pi_p4_id_t act_prof_id,
                                   size_t max_size,
                                   pi_indirect_handle_t *grp_handle) {
  return _pi_act_prof_grp_create(session_handle, dev_tgt, act_prof_id, max_size,
                                 grp_handle);
}

pi_status_t pi_act_prof_grp_delete(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t grp_handle) {
  return _pi_act_prof_grp_delete(session_handle, dev_id, act_prof_id,
                                 grp_handle);
}

pi_status_t pi_act_prof_grp_add_mbr(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t grp_handle,
                                    pi_indirect_handle_t mbr_handle) {
  return _pi_act_prof_grp_add_mbr(session_handle, dev_id, act_prof_id,
                                  grp_handle, mbr_handle);
}

pi_status_t pi_act_prof_grp_remove_mbr(pi_session_handle_t session_handle,
                                       pi_dev_id_t dev_id,
                                       pi_p4_id_t act_prof_id,
                                       pi_indirect_handle_t grp_handle,
                                       pi_indirect_handle_t mbr_handle) {
  return _pi_act_prof_grp_remove_mbr(session_handle, dev_id, act_prof_id,
                                     grp_handle, mbr_handle);
}

pi_status_t pi_act_prof_grp_set_mbrs(pi_session_handle_t session_handle,
                                     pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                     pi_indirect_handle_t grp_handle,
                                     size_t num_mbrs,
                                     const pi_indirect_handle_t *mbr_handles,
                                     const bool *activate) {
  return _pi_act_prof_grp_set_mbrs(session_handle, dev_id, act_prof_id,
                                   grp_handle, num_mbrs, mbr_handles, activate);
}

pi_status_t pi_act_prof_grp_activate_mbr(pi_session_handle_t session_handle,
                                         pi_dev_id_t dev_id,
                                         pi_p4_id_t act_prof_id,
                                         pi_indirect_handle_t grp_handle,
                                         pi_indirect_handle_t mbr_handle) {
  return _pi_act_prof_grp_activate_mbr(session_handle, dev_id, act_prof_id,
                                       grp_handle, mbr_handle);
}

pi_status_t pi_act_prof_grp_deactivate_mbr(pi_session_handle_t session_handle,
                                           pi_dev_id_t dev_id,
                                           pi_p4_id_t act_prof_id,
                                           pi_indirect_handle_t grp_handle,
                                           pi_indirect_handle_t mbr_handle) {
  return _pi_act_prof_grp_deactivate_mbr(session_handle, dev_id, act_prof_id,
                                         grp_handle, mbr_handle);
}

static void prepare_fetch_res(pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                              pi_act_prof_fetch_res_t *res) {
  res->p4info = pi_get_device_p4info(dev_id);
  res->act_prof_id = act_prof_id;
  res->idx_members = 0;
  res->idx_groups = 0;
  res->curr_members = 0;
  res->curr_groups = 0;
  res->action_datas = malloc(res->num_members * sizeof(pi_action_data_t));
}

pi_status_t pi_act_prof_entries_fetch(pi_session_handle_t session_handle,
                                      pi_dev_tgt_t dev_tgt,
                                      pi_p4_id_t act_prof_id,
                                      pi_act_prof_fetch_res_t **res) {
  pi_act_prof_fetch_res_t *res_ = malloc(sizeof(pi_act_prof_fetch_res_t));
  pi_status_t status =
      _pi_act_prof_entries_fetch(session_handle, dev_tgt, act_prof_id, res_);
  if (status != PI_STATUS_SUCCESS) {
    free(res_);
    return status;
  }

  prepare_fetch_res(dev_tgt.dev_id, act_prof_id, res_);

  *res = res_;
  return status;
}

pi_status_t pi_act_prof_mbr_fetch(pi_session_handle_t session_handle,
                                  pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                  pi_indirect_handle_t mbr_handle,
                                  pi_act_prof_fetch_res_t **res) {
  pi_act_prof_fetch_res_t *res_ = malloc(sizeof(pi_act_prof_fetch_res_t));
  pi_status_t status = _pi_act_prof_mbr_fetch(session_handle, dev_id,
                                              act_prof_id, mbr_handle, res_);
  if (status != PI_STATUS_SUCCESS) {
    free(res_);
    return status;
  }
  assert(res_->num_members == 1);
  assert(res_->num_groups == 0);

  prepare_fetch_res(dev_id, act_prof_id, res_);

  *res = res_;
  return status;
}

pi_status_t pi_act_prof_grp_fetch(pi_session_handle_t session_handle,
                                  pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                  pi_indirect_handle_t grp_handle,
                                  pi_act_prof_fetch_res_t **res) {
  pi_act_prof_fetch_res_t *res_ = malloc(sizeof(pi_act_prof_fetch_res_t));
  pi_status_t status = _pi_act_prof_grp_fetch(session_handle, dev_id,
                                              act_prof_id, grp_handle, res_);
  if (status != PI_STATUS_SUCCESS) {
    free(res_);
    return status;
  }
  assert(res_->num_members == 0);
  assert(res_->num_groups == 1);

  prepare_fetch_res(dev_id, act_prof_id, res_);

  *res = res_;
  return status;
}

pi_status_t pi_act_prof_entries_fetch_done(pi_session_handle_t session_handle,
                                           pi_act_prof_fetch_res_t *res) {
  pi_status_t status = _pi_act_prof_entries_fetch_done(session_handle, res);
  if (status != PI_STATUS_SUCCESS) return status;

  assert(res->action_datas);
  free(res->action_datas);
  free(res);
  return PI_STATUS_SUCCESS;
}

size_t pi_act_prof_mbrs_num(pi_act_prof_fetch_res_t *res) {
  return res->num_members;
}

size_t pi_act_prof_grps_num(pi_act_prof_fetch_res_t *res) {
  return res->num_groups;
}

size_t pi_act_prof_mbrs_next(pi_act_prof_fetch_res_t *res,
                             pi_action_data_t **action_data,
                             pi_indirect_handle_t *mbr_handle) {
  if (res->idx_members == res->num_members) return res->idx_members;

  size_t curr = res->curr_members;
  char *entries = res->entries_members;

  curr += retrieve_indirect_handle(entries + curr, mbr_handle);

  pi_p4_id_t action_id;
  curr += retrieve_p4_id(entries + curr, &action_id);
  uint32_t nbytes;
  curr += retrieve_uint32(entries + curr, &nbytes);
  pi_action_data_t *action_data_ = &res->action_datas[res->idx_members];
  *action_data = action_data_;
  action_data_->p4info = res->p4info;
  action_data_->action_id = action_id;
  action_data_->data_size = nbytes;
  action_data_->data = entries + curr;
  curr += nbytes;

  res->curr_members = curr;

  return res->idx_members++;
}

size_t pi_act_prof_grps_next(pi_act_prof_fetch_res_t *res,
                             pi_indirect_handle_t **mbrs, size_t *num_mbrs,
                             pi_indirect_handle_t *grp_handle) {
  if (res->idx_groups == res->num_groups) return res->idx_groups;

  size_t curr = res->curr_groups;
  char *entries = res->entries_groups;

  curr += retrieve_indirect_handle(entries + curr, grp_handle);

  uint32_t num_mbrs_;
  curr += retrieve_uint32(entries + curr, &num_mbrs_);
  *num_mbrs = num_mbrs_;
  uint32_t offset;
  curr += retrieve_uint32(entries + curr, &offset);
  *mbrs = res->mbr_handles + offset;
  res->curr_groups = curr;

  return res->idx_groups++;
}

int pi_act_prof_api_support(pi_dev_id_t dev_id) {
  return _pi_act_prof_api_support(dev_id);
}
