/*
 * Copyright 2021 SYRMIA LLC
 * SPDX-FileCopyrightText: 2021 SYRMIA LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Dusan Krdzic (dusan.krdzic@syrmia.com)
 *
 */


#ifndef PSA_SWITCH_PSA_HASH_H_
#define PSA_SWITCH_PSA_HASH_H_

#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/calculations.h>

namespace bm {

namespace psa {

class PSA_Hash : public bm::ExternType {
 public:

  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(algo);
  }

  void init() override;

  void get_hash(Field &dst, const std::vector<Field> &fields);

  void get_hash_mod(Field &dst, const Data &base, const std::vector<Field> &fields, const Data &max);

  uint64_t compute(const char *buffer, size_t s);

 private:
  std::string algo;
  std::unique_ptr<bm::CalculationsMap::MyC> calc;

};

}  // namespace bm::psa

}  // namespace bm
#endif
