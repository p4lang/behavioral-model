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

#ifndef BM_SIM_CRC_MAP_H_
#define BM_SIM_CRC_MAP_H_

#include <bm/bm_sim/calculations.h>

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

namespace bm {

class CrcMap {
 public:
  using MyC = RawCalculationIface<uint64_t>;
  using CrcFactoryFn = std::function<std::unique_ptr<MyC>()>;

  CrcMap();

  static CrcMap *get_instance();

  // see
  // http://crcmod.sourceforge.net/crcmod.predefined.html#predefined-crc-algorithms
  // for supported pre-defined crc algorithms ('-' are replaced with '_' in algo
  // names)
  std::unique_ptr<MyC> get_copy(const std::string &name) const;

  // str ::= poly_<hex-number>{_<prop_name>[_<prop_value>]}*
  // where the supported properties (prop_names) are:
  // - poly_<hex formatted string>: the polynomial to use (note: for the
  // polynomial of the power N, bit N must be set. In other words, the bit width
  // of the string has to be at least N+1). This property is mandatory.
  // - init_<hex formatted string>: the initial value of the remainder. Default
  // value is 0x0.
  // - not_rev: indicates to not use a reflecting algorithm. Default value is to
  // use reflecting algorithm
  // - xout_<hex formatted string>: a value to XOR with the final crc computed.
  // Default value is 0x0.
  // - lsb: indicates to use the least significant bits of the hash output.
  // - msb: indicates to use the most significant bits of the hash output.
  // - extend: indicates to repeat the hash output width until the desired bit
  // width is achieved.
  // lsb, msb and extend are not supported yet
  // polynomials of degree 8, 16, 32 and 64 are supported
  std::unique_ptr<MyC> get_copy_from_custom_str(const std::string &str) const;

 private:
  std::unordered_map<std::string, CrcFactoryFn> map_{};
};

}  // namespace bm

#endif  // BM_SIM_CRC_MAP_H_
