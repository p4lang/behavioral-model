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

#include "psa_internetChecksum.h"
#include <bm/bm_sim/logger.h>
#include <execinfo.h>

#define SUM_LENGTH 16

namespace bm {

namespace psa {

uint16_t
ones_complement_sum(uint16_t x, uint16_t y) {
  uint32_t _x, _y, s;
  uint16_t ret;
  _x = x;
  _y = y;
  s = _x + _y;
  if (s >> 16 == 1) {
    s = s + 1;
  }
  ret = s;
  return ret;
}

void
PSA_InternetChecksum::init() {
  sum = 0;
}

void
PSA_InternetChecksum::clear() {
  sum = 0;
}

void
PSA_InternetChecksum::add(const Field &field) {
  int len = field.get_nbits();
  // TODO give a error if len is not a multiple of 16
  Data field_val(field);

  int i = 0;
  while (i < len) {
    Data tmp(field_val);
    Data mask(0xffff);
    tmp.bit_and(tmp, mask);
    uint16_t d = tmp.get<uint16_t>();
    sum = ones_complement_sum(sum, d);
    field_val.bm::Data::shift_right(field_val, SUM_LENGTH);
    i += SUM_LENGTH;
  }
}

void
PSA_InternetChecksum::subtract(const Field &field) {
  int len = field.get_nbits();
  // TODO give a error if len is not a multiple of 16
  Data field_val(field);

  int i = 0;
  while (i < len) {
    Data tmp(field_val);
    Data mask(0xffff);
    tmp.bit_and(tmp, mask);
    uint16_t d = tmp.get<uint16_t>();
    sum = ones_complement_sum(sum, ~d);
    field_val.bm::Data::shift_right(field_val, SUM_LENGTH);
    i += SUM_LENGTH;
  }
}

void
PSA_InternetChecksum::get(Data &sum_val) {
  sum_val.set(~sum);
}

void
PSA_InternetChecksum::get_state(Data &state) {
  state.set(sum);
}

void
PSA_InternetChecksum::set_state(const Data &state) {
  sum = state.get<uint16_t>();
}

BM_REGISTER_EXTERN_W_NAME(InternetChecksum, PSA_InternetChecksum);
BM_REGISTER_EXTERN_W_NAME_METHOD(InternetChecksum, PSA_InternetChecksum, clear);
BM_REGISTER_EXTERN_W_NAME_METHOD(InternetChecksum, PSA_InternetChecksum, add, const Field &);
BM_REGISTER_EXTERN_W_NAME_METHOD(InternetChecksum, PSA_InternetChecksum, subtract, const Field &);
BM_REGISTER_EXTERN_W_NAME_METHOD(InternetChecksum, PSA_InternetChecksum, get, Data &);
BM_REGISTER_EXTERN_W_NAME_METHOD(InternetChecksum, PSA_InternetChecksum, get_state, Data &);
BM_REGISTER_EXTERN_W_NAME_METHOD(InternetChecksum, PSA_InternetChecksum, set_state, const Data &);

}  // namespace bm::psa

}  // namespace bm

int import_internetChecksum(){
  return 0;
}
