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
#include <PI/pi_meter.h>
#include <PI/target/pi_meter_imp.h>

static bool is_direct_meter(const pi_p4info_t *p4info, pi_p4_id_t meter_id) {
  return (pi_p4info_meter_get_direct(p4info, meter_id) != PI_INVALID_ID);
}

pi_status_t pi_meter_read(pi_session_handle_t session_handle,
                          pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                          size_t index, pi_meter_spec_t *meter_spec) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (is_direct_meter(p4info, meter_id)) return PI_STATUS_METER_IS_DIRECT;
  return _pi_meter_read(session_handle, dev_tgt, meter_id, index, meter_spec);
}

pi_status_t pi_meter_set(pi_session_handle_t session_handle,
                         pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                         size_t index, const pi_meter_spec_t *meter_spec) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (is_direct_meter(p4info, meter_id)) return PI_STATUS_METER_IS_DIRECT;
  pi_meter_spec_t new_spec = *meter_spec;
  if (meter_spec->meter_unit == PI_METER_UNIT_DEFAULT)
    new_spec.meter_unit =
        (pi_meter_unit_t)pi_p4info_meter_get_unit(p4info, meter_id);
  if (meter_spec->meter_type == PI_METER_TYPE_DEFAULT)
    new_spec.meter_type =
        (pi_meter_type_t)pi_p4info_meter_get_type(p4info, meter_id);
  return _pi_meter_set(session_handle, dev_tgt, meter_id, index, &new_spec);
}

pi_status_t pi_meter_read_direct(pi_session_handle_t session_handle,
                                 pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                 pi_entry_handle_t entry_handle,
                                 pi_meter_spec_t *meter_spec) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (!is_direct_meter(p4info, meter_id)) return PI_STATUS_METER_IS_NOT_DIRECT;
  return _pi_meter_read_direct(session_handle, dev_tgt, meter_id, entry_handle,
                               meter_spec);
}

pi_status_t pi_meter_set_direct(pi_session_handle_t session_handle,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                pi_entry_handle_t entry_handle,
                                const pi_meter_spec_t *meter_spec) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (!is_direct_meter(p4info, meter_id)) return PI_STATUS_METER_IS_NOT_DIRECT;
  pi_meter_spec_t new_spec = *meter_spec;
  if (meter_spec->meter_unit == PI_METER_UNIT_DEFAULT)
    new_spec.meter_unit =
        (pi_meter_unit_t)pi_p4info_meter_get_unit(p4info, meter_id);
  if (meter_spec->meter_type == PI_METER_TYPE_DEFAULT)
    new_spec.meter_type =
        (pi_meter_type_t)pi_p4info_meter_get_type(p4info, meter_id);
  return _pi_meter_set_direct(session_handle, dev_tgt, meter_id, entry_handle,
                              &new_spec);
}
