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

#ifndef PI_INC_PI_PI_METER_H_
#define PI_INC_PI_PI_METER_H_

#include <PI/pi_base.h>
#include <PI/pi_tables.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  //! default is as per the P4 program
  PI_METER_UNIT_DEFAULT = 0,
  PI_METER_UNIT_PACKETS = 1,
  PI_METER_UNIT_BYTES = 2,
} pi_meter_unit_t;

typedef enum {
  //! default is as per the P4 program
  PI_METER_TYPE_DEFAULT = 0,
  PI_METER_TYPE_COLOR_AWARE = 1,
  PI_METER_TYPE_COLOR_UNAWARE = 2,
} pi_meter_type_t;

//! Configuration for a 2-rate 3-color marker, as per RFC 2698
typedef struct {
  //! Committed information rate (units per sec)
  uint64_t cir;
  //! Committed burst size
  uint32_t cburst;
  //! Peak information rate (units per sec)
  uint64_t pir;
  //! Peak burst size
  uint32_t pburst;
  //! Meter unit (bytes / packets)
  pi_meter_unit_t meter_unit;
  //! Meter type (color-awareness)
  pi_meter_type_t meter_type;
} pi_meter_spec_t;

//! Reads an indirect meter configuration at the given \p index.
pi_status_t pi_meter_read(pi_session_handle_t session_handle,
                          pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                          size_t index, pi_meter_spec_t *meter_spec);

//! Sets an indirect meter configuration at the given \p index.
pi_status_t pi_meter_set(pi_session_handle_t session_handle,
                         pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                         size_t index, const pi_meter_spec_t *meter_spec);

//! Reads the direct meter configuration for the given \p entry_handle.
pi_status_t pi_meter_read_direct(pi_session_handle_t session_handle,
                                 pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                 pi_entry_handle_t entry_handle,
                                 pi_meter_spec_t *meter_spec);

//! Sets the direct meter configuration for the given \p entry_handle.
pi_status_t pi_meter_set_direct(pi_session_handle_t session_handle,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                pi_entry_handle_t entry_handle,
                                const pi_meter_spec_t *meter_spec);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_METER_H_
