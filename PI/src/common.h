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

#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

#include <bm/bm_sim/match_error_codes.h>

#include <PI/int/pi_int.h>
#include <PI/p4info.h>
#include <PI/pi.h>

#include <exception>
#include <string>
#include <unordered_map>
#include <vector>

namespace bm {

class SwitchWContexts;

}  // namespace bm

namespace pibmv2 {

extern bm::SwitchWContexts *switch_;

extern uint32_t cpu_port;

static inline const pi_p4info_t *get_device_info(size_t dev_id) {
  return pi_get_device_p4info(dev_id);
}

template<typename T>
static inline pi_status_t convert_error_code(T error_code) {
  return static_cast<pi_status_t>(
      PI_STATUS_TARGET_ERROR + static_cast<int>(error_code));
}

struct IndirectHMgr {
  static pi_indirect_handle_t make_grp_h(pi_indirect_handle_t h) {
    return h | grp_prefix;
  }

  static bool is_grp_h(pi_indirect_handle_t h) { return h & grp_prefix; }

  static pi_indirect_handle_t clear_grp_h(pi_indirect_handle_t h) {
    return h & (~grp_prefix);
  }

  static constexpr pi_indirect_handle_t grp_prefix =
      (1ull << (sizeof(pi_indirect_handle_t) * 8 - 1));
};

class Buffer {
 public:
  explicit Buffer(size_t capacity = 2048);

  char *extend(size_t s);

  char *copy() const;

  char *data();  // returns non-owning pointer

  size_t size() const;

 private:
  std::vector<char> data_{};
};

// We return a dummy value (0xff..ff) for the default handle. bmv2 currently
// does not support direct resources (direct counter / direct meter) for default
// entries so we will return an error if this handle is used to read / write
// direct resource configurations.
static inline constexpr pi_entry_handle_t get_default_handle() {
  return static_cast<pi_entry_handle_t>(-1);
}

}  // namespace pibmv2

#endif  // SRC_COMMON_H_
