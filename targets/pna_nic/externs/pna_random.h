/*
 * Copyright 2024 Marvell Technology, Inc.
 * SPDX-FileCopyrightText: 2024 Marvell Technology, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Rupesh Chiluka (rchiluka@marvell.com)
 *
 */

#ifndef PNA_NIC_PNA_RANDOM_H_
#define PNA_NIC_PNA_RANDOM_H_

#include <bm/bm_sim/extern.h>

namespace bm {

namespace pna {

class PNA_Random : public bm::ExternType {
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

}  // namespace bm::pna

}  // namespace bm
#endif
