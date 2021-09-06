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


#include "psa_hash.h"

namespace {

std::string
prepare_data_for_algo(const std::vector<bm::Field> &fields) {
    bm::Data help;
    bm::Data input;
    static const bm::Data mask8(0xFF);
    static const bm::Data mask4(0x0F);
    std::string buf;
    uint8_t n_bytes = 0;
    uint16_t n_bits = 0;

    // Concatenate fields in one single data
    for (int i = fields.size() - 1; i >= 0; i--) {
        help.shift_left(fields.at(i), n_bits);
        input.add(input, help);
        n_bits += fields.at(i).get_nbits();
    }

    // For an odd number of hex digits.
    // 0x456 -> 0x45 0x06
    if (n_bits % 8 != 0) {
        help.bit_and(input, mask4);
        buf.insert(buf.begin(), 1, help.get<uint8_t>());
        input.shift_right(input, 4);
        n_bits -= 4;
    }

    // Extract byte chunks
    while (!input.test_eq(0)) {
        help.bit_and(input, mask8);
        buf.insert(buf.begin(), 1, help.get<uint8_t>());
        n_bytes++;
        input.shift_right(input, 8);
    }

    // Fill with zeros to the actual size
    while (n_bytes * 8 < n_bits) {
        buf.insert(buf.begin(), 1, 0);
        n_bytes++;
    }

    return buf;
}

}  // namespace

namespace bm {

namespace psa {

void
PSA_Hash::init() {
    this->calc = bm::CalculationsMap::get_instance()->get_copy(algo);
}

void
PSA_Hash::get_hash(Field &dst, const std::vector<Field> &fields) {
    Data input(0);
    uint64_t hash;

    std::string buf = prepare_data_for_algo(fields);
    hash = compute(buf.data(), buf.size());

    dst.set(hash);
}

void
PSA_Hash::get_hash_mod(Field &dst, const Data &base, const std::vector<Field> &fields, const Data &max) {
    Data input(0);
    uint64_t hash;

    std::string buf = prepare_data_for_algo(fields);
    hash = compute(buf.data(), buf.size());

    uint64_t result = base.get<uint64_t>() + (hash % max.get<uint64_t>());

    dst.set(result);
}

uint64_t
PSA_Hash::compute(const char *buf, size_t s) {
    return this->calc.get()->output(buf, s);
}

BM_REGISTER_EXTERN_W_NAME(Hash, PSA_Hash);
BM_REGISTER_EXTERN_W_NAME_METHOD(Hash, PSA_Hash, get_hash, Field &, const std::vector<Field>);
BM_REGISTER_EXTERN_W_NAME_METHOD(Hash, PSA_Hash, get_hash_mod, Field &, const Data &, const std::vector<Field>, const Data &);

}  // namespace bm::psa

}  // namespace bm

int import_hash() {
    return 0;
}
