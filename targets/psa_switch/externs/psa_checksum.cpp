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

namespace {

void
build_buffer(const std::vector<bm::Field> &fields, bm::ByteContainer &buf) {
  int nbits = 0;
  int nbytes;
  for (const auto &field : fields) {
    nbits += field.get_nbits();
  }
  nbytes = (nbits + 7) / 8;
  nbits = (nbytes * 8 - nbits);  // pad to the left with 0s
  for (const auto &field : fields) {
    int nbits_ = nbits + field.get_nbits();
    buf.resize((nbits_ + 7) / 8, '\x00');
    char *ptr = buf.data() + (nbits / 8);
    field.deparse(ptr, nbits % 8);
    nbits = nbits_;
  }
}

}  // namespace

namespace bm {

namespace psa {

void
PSA_Checksum::init() {
  this->calc = CalculationsMap::get_instance()->get_copy(hash);
  clear();
}

void
PSA_Checksum::get(Field& dst) const {
  dst.set(internal);
}

void
PSA_Checksum::get_verify(Field& dst, Field& equOp) const {
  dst.set(equOp.get<uint64_t>() == internal);
}

void
PSA_Checksum::clear() {
  internal = 0;
}

void
PSA_Checksum::update(const std::vector<Field> fields) {
  ByteContainer buf;
  build_buffer(fields, buf);
  internal = compute(buf.data(), buf.size());
}

uint64_t
PSA_Checksum::compute(const char *buf, size_t s) {
  return this->calc.get()->output(buf, s);
}

BM_REGISTER_EXTERN_W_NAME(Checksum, PSA_Checksum);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum, update, const std::vector<Field>);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum, get, Field &);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum, get_verify, Field &, Field &);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum, clear);

}  // namespace bm::psa

}  // namespace bm

int import_checksum() {
  return 0;
}
