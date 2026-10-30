// SPDX-FileCopyrightText: 2026 Lorenzo Rinieri
//
// SPDX-License-Identifier: Apache-2.0

#include <bm/bm_sim/_assert.h>
#include <bm/bm_sim/data.h>
#include <bm/bm_sim/switch.h>

#include <PI/p4info.h>
#include <PI/pi.h>
#include <PI/target/pi_register_imp.h>

#include <cstring>
#include <string>
#include <utility>

#include "common.h"

namespace {

size_t get_register_nbytes(const pi_p4info_t *p4info, pi_p4_id_t register_id) {
  // PI common code only calls us for registers with a bitstring type
  size_t bitwidth = pi_p4info_register_get_bitwidth(p4info, register_id);
  assert(bitwidth > 0);
  return (bitwidth + 7) / 8;
}

}  // namespace

extern "C" {

pi_status_t _pi_register_read(pi_session_handle_t session_handle,
                              pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                              size_t index, char *value) {
  _BM_UNUSED(session_handle);

  const auto *p4info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(p4info != nullptr);
  std::string r_name(pi_p4info_register_name_from_id(p4info, register_id));
  size_t nbytes = get_register_nbytes(p4info, register_id);

  bm::Data data;
  auto error_code = pibmv2::switch_->register_read(0, r_name, index, &data);
  if (error_code != bm::Register::SUCCESS)
    return pibmv2::convert_error_code(error_code);
  // bmv2 masks register values to the bitwidth of the register array, so the
  // value fits unless the P4Info and the bmv2 JSON disagree on the bitwidth;
  // get_string() returns the shortest big-endian representation
  const auto bytes = data.get_string();
  if (bytes.size() > nbytes)
    return pibmv2::convert_error_code(bm::Register::ERROR);
  std::memset(value, 0, nbytes - bytes.size());
  std::memcpy(value + nbytes - bytes.size(), bytes.data(), bytes.size());
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_register_write(pi_session_handle_t session_handle,
                               pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                               size_t index, const char *value) {
  _BM_UNUSED(session_handle);

  const auto *p4info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(p4info != nullptr);
  std::string r_name(pi_p4info_register_name_from_id(p4info, register_id));
  size_t nbytes = get_register_nbytes(p4info, register_id);

  bm::Data data(value, static_cast<int>(nbytes));
  auto error_code = pibmv2::switch_->register_write(
      0, r_name, index, std::move(data));
  if (error_code != bm::Register::SUCCESS)
    return pibmv2::convert_error_code(error_code);
  return PI_STATUS_SUCCESS;
}

// register_write_range holds the lock of the register array, which is also
// taken by the actions accessing it, so the write is atomic with respect to the
// data plane: an action sees either the old value or the new one in all the
// cells
pi_status_t _pi_register_write_all(pi_session_handle_t session_handle,
                                   pi_dev_tgt_t dev_tgt,
                                   pi_p4_id_t register_id, const char *value) {
  _BM_UNUSED(session_handle);

  const auto *p4info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(p4info != nullptr);
  std::string r_name(pi_p4info_register_name_from_id(p4info, register_id));
  size_t nbytes = get_register_nbytes(p4info, register_id);
  size_t size = pi_p4info_register_get_size(p4info, register_id);

  bm::Data data(value, static_cast<int>(nbytes));
  auto error_code = pibmv2::switch_->register_write_range(
      0, r_name, 0, size, std::move(data));
  if (error_code != bm::Register::SUCCESS)
    return pibmv2::convert_error_code(error_code);
  return PI_STATUS_SUCCESS;
}

}
