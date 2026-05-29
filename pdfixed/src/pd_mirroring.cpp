// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/SimpleSwitch.h>

#include <bm/pdfixed/pd_common.h>
#include <bm/pdfixed/int/pd_conn_mgr.h>

#include <vector>

using ::sswitch_runtime::SimpleSwitchClient;

extern PdConnMgr *conn_mgr_state;

namespace {

Client<SimpleSwitchClient> client(int device) {
  return conn_mgr_state->get<SimpleSwitchClient>(device);
}

}  // namespace

extern "C" {

// TODO(unknown): remove
int p4_pd_mirroring_mapping_add(p4_pd_mirror_id_t mirror_id,
                                uint16_t egress_port) {
  (void) mirror_id; (void) egress_port;
  return 0;
}

int p4_pd_mirror_session_create(p4_pd_sess_hdl_t shdl,
                                p4_pd_dev_target_t dev_tgt,
                                p4_pd_mirror_type_e type,
                                p4_pd_direction_t dir,
                                p4_pd_mirror_id_t id,
                                uint16_t egr_port,
                                uint16_t max_pkt_len,
                                uint8_t cos,
                                bool c2c,
                                uint16_t extract_len,
                                uint32_t timeout_usec,
                                uint32_t *int_hdr,
                                uint8_t int_hdr_len) {
  (void) shdl; (void) type; (void) dir; (void) max_pkt_len; (void) cos;
  (void) c2c; (void) extract_len; (void) timeout_usec; (void) int_hdr;
  (void) int_hdr_len;
  return client(dev_tgt.device_id).c->mirroring_mapping_add(id, egr_port);
}

int p4_pd_mirror_session_update(p4_pd_sess_hdl_t shdl,
                                p4_pd_dev_target_t dev_tgt,
                                p4_pd_mirror_type_e type,
                                p4_pd_direction_t dir,
                                p4_pd_mirror_id_t id,
                                uint16_t egr_port,
                                uint16_t max_pkt_len,
                                uint8_t cos,
                                bool c2c,
                                uint16_t extract_len,
                                uint32_t timeout_usec,
                                uint32_t *int_hdr,
                                uint8_t int_hdr_len,
                                bool enable) {
  (void) shdl; (void) type; (void) dir; (void) max_pkt_len; (void) cos;
  (void) c2c; (void) extract_len; (void) timeout_usec; (void) int_hdr;
  (void) int_hdr_len; (void) enable;
  return client(dev_tgt.device_id).c->mirroring_mapping_add(id, egr_port);
}

// TODO(unknown): remove
int p4_pd_mirroring_mapping_delete(p4_pd_mirror_id_t mirror_id) {
  (void) mirror_id;
  return 0;
}

int p4_pd_mirror_session_delete(p4_pd_sess_hdl_t shdl,
                                p4_pd_dev_target_t dev_tgt,
                                p4_pd_mirror_id_t mirror_id) {
  (void) shdl;
  return client(dev_tgt.device_id).c->mirroring_mapping_delete(mirror_id);
}

int p4_pd_mirroring_mapping_get_egress_port(int mirror_id) {
  (void) mirror_id;
  return 0;
}

int p4_pd_mirroring_add_coalescing_session(const int mirror_id,
                                           const int egress_port,
                                           const int8_t *header,
                                           const int8_t header_length,
                                           const int16_t min_pkt_size,
                                           const int8_t timeout) {
  (void) mirror_id;
  (void) egress_port;
  (void) header;
  (void) header_length;
  (void) min_pkt_size;
  (void) timeout;
  return 0;
}

int p4_pd_mirroring_set_coalescing_sessions_offset(const uint16_t offset) {
  (void) offset;
  return 0;
}

}
