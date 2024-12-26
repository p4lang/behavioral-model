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
}

void PNA_IpsecAccelerator::set_sa_index(const Data &sa_index) {
    _sa_index = sa_index.get<uint32_t>();
}

void PNA_IpsecAccelerator::enable() {
    _is_enabled = true;
}

void PNA_IpsecAccelerator::disable() {
    _is_enabled = false;
}

void PNA_IpsecAccelerator::cipher(std::vector<unsigned char> input, std::vector<unsigned char> &output,
                                unsigned char key[16], unsigned char iv[16], int encrypt) {
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if (! EVP_CipherInit_ex2(ctx, EVP_aes_128_cbc(), key, iv, encrypt, NULL)) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    int outlen = 0;
    int tmplen = 0;

    if (!EVP_CipherUpdate(ctx, output.data(), &outlen, input.data(),
                            input.size())) {
        EVP_CIPHER_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        BMLOG_DEBUG("Error in CipherUpdate");
        return;
    }

    if (!EVP_CipherFinal_ex(ctx, output.data() + outlen, &tmplen)) {
        EVP_CIPHER_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        BMLOG_DEBUG("Error in CipherFinal");
        return;
    }

    outlen += tmplen;
    output.resize(outlen);
    EVP_CIPHER_CTX_free(ctx);
}

void PNA_IpsecAccelerator::decrypt(std::string string_key) {
    BMLOG_DEBUG("[IPSEC] In Decrypt");

    std::vector<unsigned char> raw_packet_data;
    raw_packet_data.resize(get_packet().get_data_size(), '\0');
    std::copy(get_packet().data(),
            get_packet().data() + get_packet().get_data_size(),
            raw_packet_data.begin());
    
    unsigned int block_size = EVP_CIPHER_block_size(EVP_aes_128_cbc());
    
    // TODO:
    // check the ICV
    // compute HMAC
    // drop the packet if ICV and the computed hmac are not the same
    unsigned char iv[block_size + 1] = {0};
    unsigned char key[string_key.length()];
    std::copy(string_key.begin(), string_key.end(), key);

    // Copy IV from the packet
    std::copy_n(raw_packet_data.begin() + ETH_HEADER_LENGTH + IP_HEADER_LENGTH 
                        + ESP_SPI_LENGTH + ESP_SEQ_LENGTH, block_size, iv);

    std::vector<unsigned char> encrypted;

    encrypted.resize(raw_packet_data.size() - ETH_HEADER_LENGTH 
                        - IP_HEADER_LENGTH - ESP_SPI_LENGTH 
                        - ESP_SEQ_LENGTH - block_size, '\0');
    std::copy(raw_packet_data.begin() + ETH_HEADER_LENGTH + IP_HEADER_LENGTH 
                    + ESP_SPI_LENGTH + ESP_SEQ_LENGTH + block_size, 
                    raw_packet_data.end(), encrypted.begin());

    std::vector <unsigned char> decrypted;
    decrypted.resize(encrypted.size() + block_size, '\0');
    
    this->cipher(encrypted, decrypted, key, iv, 0);

    int padding_length = *(decrypted.data() + decrypted.size() - NEXT_HEADER_LENGTH);

    // replace payload

    // first, remove all the data
    get_packet().remove(get_packet().get_data_size());
    // make room for the ciphertext and write the ciphertext in it
    char *payload_start = get_packet().prepend( (size_t) (decrypted.size() 
                            + ETH_HEADER_LENGTH - NEXT_HEADER_LENGTH - padding_length) );
    
    std::copy(raw_packet_data.begin(), 
                raw_packet_data.begin() + ETH_HEADER_LENGTH, 
                payload_start);
    std::copy(decrypted.begin(), 
                decrypted.end() - NEXT_HEADER_LENGTH - padding_length,
                payload_start + ETH_HEADER_LENGTH);
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
