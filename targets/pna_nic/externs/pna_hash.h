/* Copyright 2021 SYRMIA LLC
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
 * Dusan Krdzic (dusan.krdzic@syrmia.com)
 *
 */


#ifndef PNA_NIC_PNA_HASH_H_
#define PNA_NIC_PNA_HASH_H_

#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/calculations.h>

namespace bm {

namespace pna {

class PNA_Hash : public bm::ExternType {
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

}  // namespace bm::pna

}  // namespace bm
#endif
