/* Copyright 2020-present Cornell University
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
 * Yunhe Liu (yunheliu@cs.cornell.edu)
 *
 */

#ifndef PSA_SWITCH_PSA_INTERNETCHECKSUM_H_
#define PSA_SWITCH_PSA_INTERNETCHECKSUM_H_

#include <bm/bm_sim/extern.h>

namespace bm {

namespace psa {

class PSA_InternetChecksum : public bm::ExternType {
 public:
  static constexpr p4object_id_t spec_id = 0xfffffffc;

  BM_EXTERN_ATTRIBUTES {}

  void init() override;

  void clear();

  void add(const Field &field);

  void subtract(const Field &field);

  void get(Data &sum_val);

  void get_state(Data &state);

  void set_state(const Data &state);

 private:
  uint16_t sum;
};

}  // namespace bm::psa

}  // namespace bm
#endif
