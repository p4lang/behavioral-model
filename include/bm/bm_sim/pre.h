/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Srikrishna Gopu (krishna@barefootnetworks.com)
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef BM_BM_SIM_PRE_H_
#define BM_BM_SIM_PRE_H_

#include <string>
#include <bitset>

namespace bm {

namespace McPre {

template <size_t set_size>
class Set {
 public:
  using reference = typename std::bitset<set_size>::reference;

 public:
  constexpr Set() noexcept { }

  explicit Set(const std::string &str)
    : port_map(str) { }

  bool operator[] (size_t pos) const { return port_map[pos]; }
  reference operator[] (size_t pos) { return port_map[pos]; }

  constexpr size_t size() const noexcept { return port_map.size(); }

 private:
  std::bitset<set_size> port_map{};
};

}  // namespace McPre

}  // namespace bm

#endif  // BM_BM_SIM_PRE_H_
