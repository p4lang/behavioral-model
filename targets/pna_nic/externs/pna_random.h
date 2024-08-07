/* Copyright 2024 Marvell Technology, Inc.
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
