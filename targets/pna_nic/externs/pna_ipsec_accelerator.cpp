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

void PNA_IpsecAccelerator::reset() {
    _is_enabled = false;
    _sa_index = -1;
}

void PNA_IpsecAccelerator::init() {
    this->reset();

    try {
        std::string table_name = std::getenv("SAD_TABLE_NAME") ? 
                std::getenv("SAD_TABLE_NAME") : "MainControlImpl.SAD";
    
        MatchTableAbstract *table = get_p4objects().get_abstract_match_table(table_name);
        sad_table = dynamic_cast<MatchTable*>(table);
    }
    catch (std::exception &e) {
        BMLOG_DEBUG("SAD Table NOT Found");
        exit(1);
    }
}

std::string stringToHex(const std::string& input) {
    std::ostringstream hexStream;
    for (char c : input) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(c));
    }
    return hexStream.str();
}

std::string remove_leading_zeroes(std::string str) {
    int pos = str.find_first_not_of('0');

    if (pos >= 0) {
        return str.substr(pos);
    }

    return "0";
}

void PNA_IpsecAccelerator::set_sa_index(const Data &sa_index) {
    this->reset();
    
    // Retrieve the matching entry from the SAD table.
    // TODO: This is O(n) as of now. Need to optimize this ( O(1) ).
    std::string tmp_string = remove_leading_zeroes( stringToHex( sa_index.get_string() ) );

    for (MatchTable::Entry entry : sad_table->get_entries()) {
        std::string match_key = remove_leading_zeroes( stringToHex( entry.match_key[0].key ) );
        if (match_key == tmp_string) {
            _sa_index = entry.handle;
            _is_enabled = true;
        }
    }
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

void PNA_IpsecAccelerator::encrypt(std::string string_key, std::string string_iv) {
    BMLOG_DEBUG("[IPSEC] In Encrypt");

    std::vector<unsigned char> raw_packet_data;
    raw_packet_data.resize(get_packet().get_data_size(), '\0');
    std::copy(get_packet().data(),
            get_packet().data() + get_packet().get_data_size(),
            raw_packet_data.begin());

    unsigned int block_size = EVP_CIPHER_block_size(EVP_aes_128_cbc());

    unsigned char iv[block_size + 1] = {0};
    unsigned char key[block_size + 1] = {0};
    std::copy(string_iv.begin(), string_iv.end(), iv);
    std::copy(string_key.begin(), string_key.end(), key);

    std::vector<unsigned char> decrypted;
    
    decrypted.resize(raw_packet_data.size() - ETH_HEADER_LENGTH, '\0');
    std::copy(raw_packet_data.begin() + ETH_HEADER_LENGTH, raw_packet_data.end(), decrypted.begin());

    // add ESP padding
    unsigned int padding_length = block_size - ((decrypted.size() + NEXT_HEADER_LENGTH) % block_size);
    if (padding_length == block_size) {
        padding_length = 0;
    }
    for (unsigned int i = 1; i <= padding_length; ++i) {
        decrypted.push_back(static_cast<unsigned char>(i));
    }
    decrypted.push_back(padding_length);
    decrypted.push_back(0x00); // next header
    
    std::vector <unsigned char> encrypted;
    encrypted.resize(decrypted.size() + block_size, '\0');

    this->cipher(decrypted, encrypted, key, iv, 1);

    // create esp header and place the encrypted data in it.
    // prepare decrypted ipv4 header for transformation into p4 header fields
    std::vector<unsigned char> esp;
    esp.resize(ESP_SPI_LENGTH + ESP_SEQ_LENGTH + block_size + encrypted.size(), '\0');
    
    // TODO: Take these from the table entry
    size_t spi = static_cast<unsigned int>(std::time(0));

    esp[0] = (spi >> 24) & 0xFF;
    esp[1] = (spi >> 16) & 0xFF;
    esp[2] = (spi >> 8) & 0xFF;
    esp[3] = spi & 0xFF;

    size_t seq = static_cast<unsigned int>(std::time(0));

    esp[4] = (seq >> 24) & 0xFF;
    esp[5] = (seq >> 16) & 0xFF;
    esp[6] = (seq >> 8) & 0xFF;
    esp[7] = seq & 0xFF;

    std::copy(iv, iv + block_size, esp.begin() + ESP_SPI_LENGTH + ESP_SEQ_LENGTH);

    std::copy(encrypted.begin(), encrypted.end(), esp.begin() + block_size
                + ESP_SPI_LENGTH + ESP_SEQ_LENGTH);

    // TODO:
    // calculate ICV

    // replace payload

    // first, remove all the data
    get_packet().remove(get_packet().get_data_size());
    // make room for the ciphertext and write the ciphertext in it
    char *payload_start = get_packet().prepend( (size_t) (esp.size()
                            + ETH_HEADER_LENGTH + IP_HEADER_LENGTH) );
    
    std::copy(raw_packet_data.begin(), raw_packet_data.begin() + ETH_HEADER_LENGTH
                + IP_HEADER_LENGTH, payload_start);
    
    payload_start[ETH_HEADER_LENGTH + 9] = 0x32; // protocol value - ESP

    // Total length - IP
    size_t ip_total_length = IP_HEADER_LENGTH + esp.size();
    payload_start[ETH_HEADER_LENGTH + 2] = (ip_total_length >> 8) & 0xFF;
    payload_start[ETH_HEADER_LENGTH + 3] = ip_total_length & 0xFF;

    std::copy(esp.begin(), esp.end(), payload_start
                + ETH_HEADER_LENGTH + IP_HEADER_LENGTH);
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
