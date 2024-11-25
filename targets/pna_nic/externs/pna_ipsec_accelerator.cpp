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

#include "pna_ipsec_accelerator.h"

namespace bm {

namespace pna {

void PNA_IpsecAccelerator::init() {
    _is_enabled = false;
}

void PNA_IpsecAccelerator::decrypt() {
    std::vector<unsigned char> raw_packet_data;
    raw_packet_data.resize(get_packet().get_data_size(), '\0');
    std::copy(get_packet().data(),
            get_packet().data() + get_packet().get_data_size(),
            raw_packet_data.begin());

    // check the ICV
    // compute HMAC
    // drop the packet if ICV and the computed hmac are not the same
    // decrypt
    // create IV
    // std::vector<unsigned char> IV;
    unsigned char iv[17] = {0};
    unsigned char key[] = "sixteenbytes key";

    std::copy_n(raw_packet_data.begin(), 16, iv);

    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if (! EVP_DecryptInit_ex2(ctx, EVP_aes_128_cbc(), key, iv, NULL)) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);


    std::vector<unsigned char> encrypted;
    encrypted.resize(raw_packet_data.size() - 16, '\0');
    std::copy(raw_packet_data.begin() + 16, raw_packet_data.end(), encrypted.begin());

    std::vector <unsigned char> decrypted;
    decrypted.resize(encrypted.size() + 16, '\0');
    
    int outlen = 0;
    int tmplen = 0;

    if (!EVP_DecryptUpdate(ctx, decrypted.data(), &outlen, encrypted.data(),
                            encrypted.size())) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        std::cout << "Error in DecryptUpdate" << std::endl;
        return;
    }

    if (!EVP_DecryptFinal_ex(ctx, decrypted.data() + outlen, &tmplen)) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        std::cout << "Error in DecryptFinal" << std::endl;
        return;
    }

    outlen += tmplen;
    decrypted.resize(outlen); // resize vector to actual output length
    EVP_CIPHER_CTX_free(ctx);

    // padding length
    int padding_length = *(decrypted.data() + encrypted.size() - 2);
    
    // payload
    std::vector<unsigned char> payload;
    payload.resize(decrypted.size() - 2 - padding_length, '\0');
    std::copy(decrypted.begin(), decrypted.end() - 2 - padding_length, payload.begin());

    // replace payload
    // first, remove all the data
    get_packet().remove(get_packet().get_data_size());
    // make room for the ciphertext and write the ciphertext in it
    char *payload_start = get_packet().prepend(
        (size_t) decrypted.size() - 2 - padding_length);
    // 2 = padding length + next header
    for (uint i =0; i < (size_t) decrypted.size() - 2 - padding_length; i++) {
        payload_start[i] = payload[i];
    }
}

void PNA_IpsecAccelerator::encrypt() {
}

void PNA_IpsecAccelerator::set_sa_index(const Data &sa_index) {
    _sa_index = sa_index.get<uint32_t>();
}

void PNA_IpsecAccelerator::enable() {
    _is_enabled = true;
    decrypt();
}

void PNA_IpsecAccelerator::disable() {
    _is_enabled = false;
}

BM_REGISTER_EXTERN_W_NAME(ipsec_accelerator, PNA_IpsecAccelerator);
BM_REGISTER_EXTERN_W_NAME_METHOD(ipsec_accelerator, PNA_IpsecAccelerator, set_sa_index, const Data &);
BM_REGISTER_EXTERN_W_NAME_METHOD(ipsec_accelerator, PNA_IpsecAccelerator, enable);
BM_REGISTER_EXTERN_W_NAME_METHOD(ipsec_accelerator, PNA_IpsecAccelerator, disable);

}  // namespace bm::pna

}  // namespace bm

int import_ipsec_accelerator() {
    return 0;
}
