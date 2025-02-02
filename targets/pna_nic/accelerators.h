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

#ifndef PNA_NIC_ACCELERATORS_H_
#define PNA_NIC_ACCELERATORS_H_

#include <bm/bm_sim/context.h>
#include <bm/bm_sim/logger.h>

#include "externs/pna_ipsec_accelerator.h"

namespace bm {

namespace pna {

class Accelerators {
 public:
  Accelerators(Context *context);

  void apply();

 private:
  Context *ctx;
};

} // namespace bm

} // namespace pna

#endif // PNA_NIC_ACCELERATORS_H_
