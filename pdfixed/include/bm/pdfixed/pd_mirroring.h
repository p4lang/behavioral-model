/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef BM_PDFIXED_PD_MIRRORING_H_
#define BM_PDFIXED_PD_MIRRORING_H_

#ifdef __cplusplus
extern "C" {
#endif


/* return 0 if success */

int p4_pd_mirroring_mapping_add(p4_pd_mirror_id_t mirror_id,
                                uint16_t egress_port);

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
                               uint8_t int_hdr_len);

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
                                bool enable);

int p4_pd_mirroring_mapping_delete(p4_pd_mirror_id_t mirror_id);

int p4_pd_mirror_session_delete(p4_pd_sess_hdl_t shdl,
                                p4_pd_dev_target_t dev_tgt,
                                p4_pd_mirror_id_t mirror_id);

int p4_pd_mirroring_mapping_get_egress_port(int mirror_id);

int p4_pd_mirroring_add_coalescing_session(const int mirror_id,
                                           const int egress_port,
                                           const int8_t *header,
                                           const int8_t header_length,
                                           const int16_t min_pkt_size,
                                           const int8_t timeout);

int p4_pd_mirroring_set_coalescing_sessions_offset(const uint16_t offset);

#ifdef __cplusplus
}
#endif

#endif  // BM_PDFIXED_PD_MIRRORING_H_
