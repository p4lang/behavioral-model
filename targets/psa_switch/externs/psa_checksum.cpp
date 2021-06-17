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


#include "psa_checksum.h"

namespace bm {

namespace psa {

void
PSA_Checksum::init() {
  this->clear();
}

void
PSA_Checksum::get(Field& dst) const {
  dst.set(internal.get<uint64_t>());
}

void
PSA_Checksum::get_verify(Field& dst, Field& equOp) const {
  if (equOp.get<uint64_t>()!=internal.get<uint64_t>()) {
    dst.set(false);
  } else {
    dst.set(true);
  }
}

void
PSA_Checksum::clear() {
  internal.set(0);
}

void
PSA_Checksum::update(const NamedCalculation& calculation) {
  const uint64_t cksum = calculation.output(get_packet());
  this->internal.set(cksum);
}

BM_REGISTER_EXTERN_W_NAME(Checksum,PSA_Checksum);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum,update, const NamedCalculation&);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum,get, Field &);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum,get_verify, Field &, Field &);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum,clear);

}  // namespace bm::psa

}  // namespace bm

int import_checksums() {
  return 0;
}
