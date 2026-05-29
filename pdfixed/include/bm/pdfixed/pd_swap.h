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

#ifndef BM_PDFIXED_PD_SWAP_H_
#define BM_PDFIXED_PD_SWAP_H_

#include <bm/pdfixed/pd_common.h>

#ifdef __cplusplus
extern "C" {
#endif

p4_pd_status_t
p4_pd_load_new_config(p4_pd_sess_hdl_t shdl, uint8_t dev_id,
                      const char *config_str);

p4_pd_status_t
p4_pd_swap_configs(p4_pd_sess_hdl_t shdl, uint8_t dev_id);

#ifdef __cplusplus
}
#endif

#endif  // BM_PDFIXED_PD_SWAP_H_
