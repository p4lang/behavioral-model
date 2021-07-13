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


#include "psa_internet_checksum.h"
#include <bm/bm_sim/_assert.h>


namespace {

uint16_t 
ones_complement_sum(uint16_t x, uint16_t y) {
    uint32_t ret = (uint32_t) x + (uint32_t) y; 
    if (ret >= 0x10000) 
        ret++;

    return ret;
}

}  // namespace

namespace bm {

namespace psa {

void
PSA_InternetChecksum::init() {
    clear();
}

void
PSA_InternetChecksum::get(Field &dst) const {
    dst.set(static_cast<uint16_t>(~sum));
}

void
PSA_InternetChecksum::get_state(Field &dst) const {
    dst.set(sum);
}

void
PSA_InternetChecksum::get_verify(Field &dst, Field &equOp) const {
    dst.set(equOp.get<uint16_t>() == static_cast<uint16_t>(~sum));
}

void
PSA_InternetChecksum::set_state(const Data &src) {
    sum = src.get<uint16_t>();
}

void
PSA_InternetChecksum::clear() {
    sum = 0;
}

void
PSA_InternetChecksum::add(const std::vector<Field> fields) {
    bm::Data input(0);
    uint16_t current_bits_offset = 0;
    const uint8_t base = 16;

    // Concatenate fields in one single data
    for(int i = fields.size() - 1 ; i >= 0 ; i--) {
        bm::Data shift_value;
        shift_value.shift_left(bm::Data(fields.at(i).get<uint64_t>()), current_bits_offset);
        input.add(input, shift_value);
        current_bits_offset += fields.at(i).get_nbits();
    }

    _BM_ASSERT(current_bits_offset % 16 == 0);

    while(input != 0) {
        uint16_t d = input.get<uint16_t>();
        sum = ones_complement_sum(sum, d);
        input.shift_right(input, base);
    }
}

void
PSA_InternetChecksum::subtract(const std::vector<Field> fields) {
    bm::Data input(0);
    uint16_t current_bits_offset = 0;
    const uint8_t base = 16;

    // Concatenate fields in one single data
    for(int i = fields.size() - 1 ; i >= 0 ; i--) {
        bm::Data shift_value;
        shift_value.shift_left(bm::Data(fields.at(i).get<uint64_t>()), current_bits_offset);
        input.add(input, shift_value);
        current_bits_offset += fields.at(i).get_nbits();
    }

    _BM_ASSERT(current_bits_offset % 16 == 0);

    while(input != 0) {
        uint16_t d = input.get<uint16_t>();
        sum = ones_complement_sum(sum, ~d);
        input.shift_right(input, base);
    }
}


BM_REGISTER_EXTERN_W_NAME(InternetChecksum, PSA_InternetChecksum);
BM_REGISTER_EXTERN_W_NAME_METHOD(InternetChecksum, PSA_InternetChecksum, add, const std::vector<Field>);
BM_REGISTER_EXTERN_W_NAME_METHOD(InternetChecksum, PSA_InternetChecksum, subtract, const std::vector<Field>);
BM_REGISTER_EXTERN_W_NAME_METHOD(InternetChecksum, PSA_InternetChecksum, get_state, Field &);
BM_REGISTER_EXTERN_W_NAME_METHOD(InternetChecksum, PSA_InternetChecksum, set_state,const Data &);
BM_REGISTER_EXTERN_W_NAME_METHOD(InternetChecksum, PSA_InternetChecksum, get, Field &);
BM_REGISTER_EXTERN_W_NAME_METHOD(InternetChecksum, PSA_InternetChecksum, get_verify, Field &, Field &);
BM_REGISTER_EXTERN_W_NAME_METHOD(InternetChecksum, PSA_InternetChecksum, clear);

}  // namespace bm::psa

}  // namespace bm

int import_internet_checksum() {
    return 0;
}
