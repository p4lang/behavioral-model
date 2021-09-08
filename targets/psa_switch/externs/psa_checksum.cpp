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

std::string
build_buffer(const std::vector<bm::Field> &fields) {
  bm::Data help;
  bm::Data input;
  static const bm::Data mask(0xFF);
  std::string buf;
  uint16_t n_bits = 0;

  // Concatenate fields in one single data
  for (int i = fields.size() - 1; i >= 0; i--) {
    help.shift_left(fields.at(i), n_bits);
    input.add(input, help);
    n_bits += fields.at(i).get_nbits();
  }

  // Extract byte chunks
  while (!input.test_eq(0)) {
    help.bit_and(input, mask);
    buf.insert(buf.begin(), 1, help.get<uint8_t>());
    input.shift_right(input, 8);
  }

  return buf;
}

}  // namespace

namespace bm {

namespace psa {

void
PSA_Checksum::init() {
  this->calc = bm::CalculationsMap::get_instance()->get_copy(hash);
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
  Data input(0);

  std::string buf = build_buffer(fields);
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
