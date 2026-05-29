/*
 * SPDX-FileCopyrightText: 2020 Cornell University
 * Copyright 2020-present Cornell University
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Yunhe Liu (yunheliu@cs.cornell.edu)
 *
 */

#ifndef PSA_SWITCH_PSA_RANDOM_H_
#define PSA_SWITCH_PSA_RANDOM_H_

#include <bm/bm_sim/extern.h>

namespace bm {

namespace psa {

class PSA_Random : public bm::ExternType {
 public:
  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(min);
    BM_EXTERN_ATTRIBUTE_ADD(max);
  }

  void init() override;

  void read(Data &value);

 private:
  Data min;
  Data max;
  uint64_t min_val;
  uint64_t max_val;
};

}  // namespace bm::psa

}  // namespace bm
#endif
