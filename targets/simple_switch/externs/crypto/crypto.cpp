/* Copyright 2013-present Barefoot Networks, Inc.
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
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */
// aes stuff
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/tables.h>
#include <bm/bm_sim/logger.h>
// needed for externs
#include <bm/bm_sim/extern.h>
#include <unistd.h>

#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <mutex>
#include <sstream>

#include "simple_switch.h"

using namespace bm;
using std::endl;
using std::cout;
using std::string;
using std::vector;

#define SAK_SIZE 16
#define SCI_SIZE 8
#define PN_SIZE 4
#define ADDR_SIZE 6
#define SECTAG_SIZE 16
#define ICV_SIZE 16
#define IPV4_HDR_SIZE 20
#define ETHERTYPE_SIZE 2

#define SECURE_DATA_SIZE 123

class ExternCrypt : public ExternType {
 public:
  BM_EXTERN_ATTRIBUTES {
  }

  void init() override {
  }
  void protect(const Data &in_sak,
                const Data &in_sci,
                const Data &in_pn,
                const Data &in_src_addr,
                const Data &in_dst_addr,
                const Data &in_sectag,
                const Data &in_ethertype,
                const Data &in_prepend_ipv4_hdr,
                const Data &in_ipv4_hdr) {
    std::vector<unsigned char> secure_association_key = get_char_vector(
                                          in_sak.get_string(), SAK_SIZE);
    // cout << "[p4sec] secure_association_key" << std::endl;
    // hexdump((char*)&secure_association_key[0],
    // secure_association_key.size());

    std::vector<unsigned char> secure_channel_identifier =
      get_char_vector(in_sci.get_string(), SCI_SIZE);
    // cout << "[p4sec] secure_channel_identifier" << std::endl;
    // hexdump((char*)&secure_channel_identifier[0],
    // secure_channel_identifier.size());

    std::vector<unsigned char> packet_number =
        get_char_vector(in_pn.get_string(), PN_SIZE);
    // cout << "[p4sec] packet_number" << std::endl;
    // hexdump((char*)&packet_number[0], packet_number.size());

    std::vector<unsigned char> source_mac_address =
      get_char_vector(in_src_addr.get_string(), ADDR_SIZE);
    // cout << "[p4sec] source_mac_address" << std::endl;
    // hexdump((char*)&source_mac_address[0], source_mac_address.size());

    std::vector<unsigned char> destionation_mac_address =
      get_char_vector(in_dst_addr.get_string(), ADDR_SIZE);
    // cout << "[p4sec] destionation_mac_address" << std::endl;
    // hexdump((char*)&destionation_mac_address[0],
    // destionation_mac_address.size());

    std::vector<unsigned char> security_tag =
      get_char_vector(in_sectag.get_string(), SECTAG_SIZE);
    // cout << "[p4sec] security_tag" << std::endl;
    // hexdump((char*)&security_tag[0], security_tag.size());

    std::vector<unsigned char> ethertype =
      get_char_vector(in_ethertype.get_string(), ETHERTYPE_SIZE);
    // cout << "[p4sec] EtherType" << std::endl;
    // hexdump((char*)&ethertype[0], ethertype.size());

    bool prepend_ipv4 = false;
    // must pass byte to external function
    // use 0x54 T as true
    // use 0x46 F as false
    // cout << "[p4sec] prepend IPv4 Header ? "
    // << in_prepend_ipv4_hdr.get_string() << std::endl;
    if (in_prepend_ipv4_hdr.get_string().compare("T") == 0) {
      prepend_ipv4 = true;
      // cout << "[p4sec] prepend IPv4 Header" << std::endl;
    } else {
      // cout << "[p4sec] do not prepend IPv4 Header" << std::endl;
    }

    std::vector<unsigned char> ipv4_hdr;
    if (prepend_ipv4) {
      ipv4_hdr = get_char_vector(in_ipv4_hdr.get_string(), IPV4_HDR_SIZE);
      // cout << "[p4sec] IPv4 Header" << std::endl;
      // hexdump((char*)&ipv4_hdr[0], ipv4_hdr.size());
    }


    vector<unsigned char> raw_packet_data;
    // calculate secure data length
    int raw_packet_size = get_packet().get_data_size() + ETHERTYPE_SIZE;
    if (prepend_ipv4) {
      raw_packet_size += IPV4_HDR_SIZE;
    }
    raw_packet_data.resize(raw_packet_size, '\0');
    // copy EtherType
    vector<unsigned char>::iterator copy_pointer = raw_packet_data.begin();
    std::copy(ethertype.data(), ethertype.data() + ETHERTYPE_SIZE,
      copy_pointer);
    copy_pointer += ETHERTYPE_SIZE;
    // copy IPv4 Header if necessary
    if (prepend_ipv4) {
      std::copy(ipv4_hdr.data(), ipv4_hdr.data() + IPV4_HDR_SIZE,
        copy_pointer);
      copy_pointer += IPV4_HDR_SIZE;
    }
    // copy payload
    std::copy(get_packet().data(),
              get_packet().data() + get_packet().get_data_size(),
              copy_pointer);


    std::vector<unsigned char> secure_data;
    secure_data.reserve(raw_packet_size);
    std::vector<unsigned char> integrity_check_value;
    integrity_check_value.reserve(ICV_SIZE);

    protection_function(secure_association_key, secure_channel_identifier,
                        packet_number, destionation_mac_address,
                        source_mac_address, security_tag, raw_packet_data,
                        secure_data, integrity_check_value);

    // cout << "[p4sec] secure_data" << std::endl;
    // hexdump((char*)&secure_data[0], secure_data.size());

    // cout << "[p4sec] integrity_check_value" << std::endl;
    // hexdump((char*)&integrity_check_value[0], integrity_check_value.size());

    // replace payload
    // first, remove all the data
    get_packet().remove(get_packet().get_data_size());
    // make room for the ciphertext and write the ciphertext in it
    char *payload_start = get_packet().prepend(
                           static_cast<uint64_t> (secure_data.size() +
                           integrity_check_value.size()));
    for (uint i = 0; i < secure_data.size(); i++) {
      payload_start[i] = secure_data[i];
    }
    for (uint i = 0; i < integrity_check_value.size(); i++) {
      payload_start[i + secure_data.size()] = integrity_check_value[i];
    }
  }

  void validate(const Data &in_sak,
                const Data &in_sci,
                const Data &in_pn,
                const Data &in_src_addr,
                const Data &in_dst_addr,
                const Data &in_sectag,
                Data &out_valid,
                Data &out_ethertype) {
    std::vector<unsigned char> secure_association_key =
         get_char_vector(in_sak.get_string(), SAK_SIZE);
    // cout << "[p4sec] secure_association_key" << std::endl;
    // hexdump((char*)&secure_association_key[0],
    // secure_association_key.size());

    std::vector<unsigned char> secure_channel_identifier =
            get_char_vector(in_sci.get_string(), SCI_SIZE);
    // cout << "[p4sec] secure_channel_identifier" << std::endl;
    // hexdump((char*)&secure_channel_identifier[0],
    // secure_channel_identifier.size());

    std::vector<unsigned char> packet_number = get_char_vector(
                                    in_pn.get_string(), PN_SIZE);
    // cout << "[p4sec] packet_number" << std::endl;
    // hexdump((char*)&packet_number[0], packet_number.size());

    std::vector<unsigned char> source_mac_address = get_char_vector(
                                in_src_addr.get_string(), ADDR_SIZE);
    // cout << "[p4sec] source_mac_address" << std::endl;
    // hexdump((char*)&source_mac_address[0], source_mac_address.size());

    std::vector<unsigned char> destionation_mac_address =
     get_char_vector(in_dst_addr.get_string(), ADDR_SIZE);
    // cout << "[p4sec] destionation_mac_address" << std::endl;
    // hexdump((char*)&destionation_mac_address[0],
    // destionation_mac_address.size());

    std::vector<unsigned char> security_tag = get_char_vector(
                          in_sectag.get_string(), SECTAG_SIZE);
    // cout << "[p4sec] security_tag" << std::endl;
    // hexdump((char*)&security_tag[0], security_tag.size());

    std::vector<unsigned char> secure_data;
    // calculate secure data length
    int secure_data_size = get_packet().get_data_size() - ICV_SIZE;
    secure_data.resize(secure_data_size, '\0');

    std::vector<unsigned char> integrity_check_value;
    integrity_check_value.resize(ICV_SIZE, '\0');

    // copy secure data
    std::copy(get_packet().data(),
              get_packet().data() + get_packet().get_data_size() - ICV_SIZE,
              secure_data.begin());

    // copy ICV
    std::copy(get_packet().data() + get_packet().get_data_size() - ICV_SIZE,
              get_packet().data() + get_packet().get_data_size(),
              integrity_check_value.begin());

    // cout << "[p4sec] secure_data" << std::endl;
    // hexdump((char*)&secure_data[0], secure_data.size());

    // cout << "[p4sec] integrity_check_value" << std::endl;
    // hexdump((char*)&integrity_check_value[0], integrity_check_value.size());

    std::vector<unsigned char> user_data;
    user_data.reserve(secure_data_size);

    int valid = validation_function(secure_association_key,
                                    secure_channel_identifier,
                                    packet_number,
                                    destionation_mac_address,
                                    source_mac_address,
                                    security_tag, secure_data,
                                    integrity_check_value, user_data);

    // cout << "[p4sec] user_data" << std::endl;
    // hexdump((char*)&user_data[0], user_data.size());

    // cout << "[p4sec] Ethertype" << std::endl;
    // hexdump((char*)&user_data[0], ETHERTYPE_SIZE);

    // cout << "[p4sec] decrypted payload" << std::endl;
    // hexdump((char*)&user_data[ETHERTYPE_SIZE],
    // user_data.size() - ETHERTYPE_SIZE);

    // replace payload
    // first, remove all the data
    get_packet().remove(get_packet().get_data_size());
    // make room for the ciphertext and write the ciphertext in it
    char *payload_start = get_packet().prepend(
                          static_cast<uint64_t> (secure_data.size()
                          + user_data.size()));
    for (uint i = 0; i < user_data.size() - ETHERTYPE_SIZE; i++) {
      payload_start[i] = user_data[i + ETHERTYPE_SIZE];
    }

    // copy ethertype from encrypted packet
    std::stringstream ss_ethertype;
    for (uint i = 0; i < ETHERTYPE_SIZE; ++i)
      ss_ethertype << std::setfill('0') << std::setw(2) << std::hex
      << static_cast<int>(user_data[i]);
    std::string ethertype_hexstr = ss_ethertype.str();

    out_ethertype.set(ethertype_hexstr);
    out_valid.set(valid);
  }

  std::vector<unsigned char> get_char_vector(string str, uint size) {
    // string fitted_str = fit_string(str, size);
    std::vector<unsigned char> vec(size, '\0');
    if (str.length() > size) {
      // cout << "[p4sec] given string was too long" << std::endl;
      str.resize(size);
    }
    vec.insert(vec.cend()-size, str.begin(), str.end());

    return vec;
  }

  void protection_function(std::vector<unsigned char> secure_association_key,
                           std::vector<unsigned char> secure_channel_identifier,
                           std::vector<unsigned char> packet_number,
                           std::vector<unsigned char> destionation_mac_address,
                           std::vector<unsigned char> source_mac_address,
                           std::vector<unsigned char> security_tag,
                           std::vector<unsigned char> user_data,
                           std::vector<unsigned char>& out_secure_data,
                           std::vector<unsigned char>& out_integrity_check_value
                          ) {
    // hier evtl assertions fuer die Laenge der Parameter
    //
    // std::cout << "[p4sec] secure_association_key size "
    // << secure_association_key.size() <<  std::endl;
    // hexdump((char*)&secure_association_key[0],
    // secure_association_key.size());

    // std::cout << "[p4sec] secure_channel_identifier size "
    // << secure_channel_identifier.size() <<  std::endl;
    // hexdump((char*)&secure_channel_identifier[0],
    // secure_channel_identifier.size());

    // std::cout << "[p4sec] packet_number size "
    // << packet_number.size() <<  std::endl;
    // hexdump((char*)&packet_number[0], packet_number.size());

    // std::cout << "[p4sec] destionation_mac_address size "
    // << destionation_mac_address.size() <<  std::endl;
    // hexdump((char*)&destionation_mac_address[0],
    // destionation_mac_address.size());

    // std::cout << "[p4sec] source_mac_address size "
    // << source_mac_address.size() <<  std::endl;
    // hexdump((char*)&source_mac_address[0], source_mac_address.size());

    // std::cout << "[p4sec] security_tag size " <<
    // security_tag.size() <<  std::endl;
    // hexdump((char*)&security_tag[0], security_tag.size());

    // std::cout << "[p4sec] user_data size " <<
    // user_data.size() <<  std::endl;
    // hexdump((char*)&user_data[0], user_data.size());


    // terms K, IV, A, P, C, T used in section 2.1 of the GCM
    // specification ( GCM ) as submitted to NIST

    // 128 bit key
    std::vector<unsigned char> K;
    K.reserve(secure_association_key.size());
    K.insert(K.cend(), secure_association_key.cbegin(),
             secure_association_key.cend());

    // std::cout << "[p4sec] K size " << K.size() <<  std::endl;
    // hexdump((char*)&K[0], K.size());

    // 12 byte IV
    std::vector<unsigned char> IV;
    IV.reserve(secure_channel_identifier.size() + packet_number.size());
    // The 64 most significant bits of the 96-bit IV are the octets
    // of the SCI, encoded as a binary number (9.1).
    IV.insert(IV.cend(), secure_channel_identifier.cbegin(),
              secure_channel_identifier.cend());
    // The 32 least significant bits of the 96-bit IV are the octets
    // of the PN, encoded as a binary number
    IV.insert(IV.cend(), packet_number.cbegin(), packet_number.cend());

    // std::cout << "[p4sec] IV size " << IV.size() <<  std::endl;
    // hexdump((char*)&IV[0], IV.size());


    // A is the Destination MAC Address, Source MAC Address,
    // and the octets of the SecTAG concatenated in that order
    std::vector<unsigned char> A;
    A.reserve(destionation_mac_address.size() +
              source_mac_address.size() + security_tag.size());
    A.insert(A.cend(), destionation_mac_address.cbegin(),
             destionation_mac_address.cend());
    A.insert(A.cend(), source_mac_address.cbegin(), source_mac_address.cend());
    A.insert(A.cend(), security_tag.cbegin(), security_tag.cend());

    // P is the octets of the User Data
    std::vector<unsigned char> P;
    P.reserve(user_data.size());
    P.insert(P.cend(), user_data.cbegin(), user_data.cend());

    out_secure_data.resize(P.size(), '\0');
    out_integrity_check_value.resize(16, '\0');


    // std::cout << "[p4sec] out_secure_data size " <<
    // out_secure_data.size() <<  std::endl;
    // hexdump((char*)&out_secure_data[0], out_secure_data.size());

    // std::cout << "[p4sec] out_integrity_check_value size "
    // << out_integrity_check_value.size() <<  std::endl;
    // hexdump((char*)&out_integrity_check_value[0],
    // out_integrity_check_value.size());

    // std::cout << "[p4sec] initilalizing encryption" << std::endl;
    int actual_size = 0, final_size = 0;
    EVP_CIPHER_CTX* e_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(e_ctx, EVP_aes_128_gcm(), &K[0], &IV[0]);

    // Set the IV length, kann man machen, muss man aber nicht da standard 12
    // EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    // https://www.openssl.org/docs/man1.0.2/crypto/EVP_get_cipherbynid.html#GCM_Mode
    // To specify any additional authenticated data (AAD) a call
    // to EVP_CipherUpdate(), EVP_EncryptUpdate() or EVP_DecryptUpdate()
    // should be made with the output parameter out set to NULL
    EVP_EncryptUpdate(e_ctx, NULL, &actual_size, &A[0], A.size());
    EVP_EncryptUpdate(e_ctx, &out_secure_data[0], &actual_size,
                      &P[0], P.size());
    EVP_EncryptFinal(e_ctx, &out_secure_data[actual_size], &final_size);
    EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_GET_TAG, 16,
                        &out_integrity_check_value[0]);
    EVP_CIPHER_CTX_free(e_ctx);
  }

  int validation_function(std::vector<unsigned char> secure_association_key,
                          std::vector<unsigned char> secure_channel_identifier,
                          std::vector<unsigned char> packet_number,
                          std::vector<unsigned char> destionation_mac_address,
                          std::vector<unsigned char> source_mac_address,
                          std::vector<unsigned char> security_tag,
                          std::vector<unsigned char> secure_data,
                          std::vector<unsigned char> integrity_check_value,
                          std::vector<unsigned char>& out_user_data) {
      // std::cout << "[p4sec] secure_association_key size "
      // << secure_association_key.size() <<  std::endl;
      // hexdump((char*)&secure_association_key[0],
      // secure_association_key.size());

      // std::cout << "[p4sec] secure_channel_identifier size "
      // << secure_channel_identifier.size() <<  std::endl;
      // hexdump((char*)&secure_channel_identifier[0],
      // secure_channel_identifier.size());

      // std::cout << "[p4sec] packet_number size "
      // << packet_number.size() <<  std::endl;
      // hexdump((char*)&packet_number[0], packet_number.size());

      // std::cout << "[p4sec] destionation_mac_address size "
      // << destionation_mac_address.size() <<  std::endl;
      // hexdump((char*)&destionation_mac_address[0],
      // destionation_mac_address.size());

      // std::cout << "[p4sec] source_mac_address size "
      // << source_mac_address.size() <<  std::endl;
      // hexdump((char*)&source_mac_address[0], source_mac_address.size());

      // std::cout << "[p4sec] security_tag size "
      // << security_tag.size() <<  std::endl;
      // hexdump((char*)&security_tag[0], security_tag.size());

      // std::cout << "[p4sec] secure_data size "
      // << secure_data.size() <<  std::endl;
      // hexdump((char*)&secure_data[0], secure_data.size());

      // std::cout << "[p4sec] integrity_check_value size "
      // << integrity_check_value.size() <<  std::endl;
      // hexdump((char*)&integrity_check_value[0],
      // integrity_check_value.size());


      // terms K, IV, A, P, C, T used in section 2.1 of the GCM
      // specification ( GCM ) as submitted to NIST

      // 128 bit key
      std::vector<unsigned char> K;
      K.reserve(secure_association_key.size());
      K.insert(K.cend(), secure_association_key.cbegin(),
               secure_association_key.cend());

      // std::cout << "[p4sec] K size " << K.size() <<  std::endl;
      // hexdump((char*)&K[0], K.size());

      // 12 byte IV
      std::vector<unsigned char> IV;
      IV.reserve(secure_channel_identifier.size() + packet_number.size());
      // The 64 most significant bits of the 96-bit IV are the octets of
      // the SCI, encoded as a binary number (9.1).
      IV.insert(IV.cend(), secure_channel_identifier.cbegin(),
                secure_channel_identifier.cend());
      // The 32 least significant bits of the 96-bit IV are the octets of
      // the PN, encoded as a binary number
      IV.insert(IV.cend(), packet_number.cbegin(), packet_number.cend());

      // std::cout << "[p4sec] IV size " << IV.size() <<  std::endl;
      // hexdump((char*)&IV[0], IV.size());


      // A is the Destination MAC Address, Source MAC Address, and
      // the octets of the SecTAG concatenated in that order
      std::vector<unsigned char> A;
      A.reserve(destionation_mac_address.size() +
                source_mac_address.size() + security_tag.size());
      A.insert(A.cend(), destionation_mac_address.cbegin(),
               destionation_mac_address.cend());
      A.insert(A.cend(), source_mac_address.cbegin(),
              source_mac_address.cend());
      A.insert(A.cend(), security_tag.cbegin(), security_tag.cend());

      // P is the octets of the User Data
      std::vector<unsigned char> P;
      P.reserve(secure_data.size());
      P.insert(P.cend(), secure_data.cbegin(), secure_data.cend());

      out_user_data.resize(P.size(), '\0');

      int actual_size = 0, final_size = 0;
      EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
      EVP_DecryptInit(d_ctx, EVP_aes_128_gcm(), &K[0], &IV[0]);

      // https://www.openssl.org/docs/man1.0.2/crypto/EVP_get_cipherbynid.html#GCM_Mode
      // To specify any additional authenticated data (AAD) a call to
      // EVP_CipherUpdate(), EVP_EncryptUpdate() or EVP_DecryptUpdate() should
      // be made with the output parameter out set to NULL
      EVP_DecryptUpdate(d_ctx, NULL, &actual_size, &A[0], A.size());

      EVP_DecryptUpdate(d_ctx, &out_user_data[0], &actual_size,
                        &P[0], P.size() );
      EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, 16,
                          &integrity_check_value[0]);
      int result = EVP_DecryptFinal(d_ctx, &out_user_data[actual_size],
                                    &final_size);

      if (result == 1) {
        // valid result
      } else {
        // decryption failed
        // -> abprt/drop packet?
      }

      // std::cout << "result of decryption: " << result << std::endl;


      EVP_CIPHER_CTX_free(d_ctx);

      return result;
  }

  void hexDump(char *addr, int len) {
      int i;
      unsigned char buff[17];
      unsigned char *pc = (unsigned char*)addr;
      // Process every byte in the data.
      for (i = 0; i < len; i++) {
          // Multiple of 16 means new line (with line offset).

          if ((i % 16) == 0) {
              // Just don't print ASCII for the zeroth line.
              if (i != 0)
                  printf("  %s\n", buff);

              // Output the offset.
              printf("[p4sec]  %04x ", i);
          }

          // Now the hex code for the specific character.
          printf(" %02x", pc[i]);

          // And store a printable ASCII character for later.
          if ((pc[i] < 0x20) || (pc[i] > 0x7e))
              buff[i % 16] = '.';
          else
              buff[i % 16] = pc[i];
          buff[(i % 16) + 1] = '\0';
      }

      // Pad out last line if not exactly 16 characters.
      while ((i % 16) != 0) {
          printf("   ");
          i++;
      }

      // And print the final ASCII bit.
      printf("  %s\n", buff);
  }
};

// do not put these inside an anonymous namespace or some compilers may complain
BM_REGISTER_EXTERN(ExternCrypt);
BM_REGISTER_EXTERN_METHOD(ExternCrypt, protect, const Data &, const Data &,
                          const Data &, const Data &, const Data &,
                          const Data &, const Data &, const Data &,
                          const Data &);
BM_REGISTER_EXTERN_METHOD(ExternCrypt, validate, const Data &, const Data &,
                          const Data &, const Data &, const Data &,
                          const Data &, Data &, Data &);
BM_REGISTER_EXTERN_W_NAME(ext_crypt, ExternCrypt);
BM_REGISTER_EXTERN_W_NAME_METHOD(ext_crypt, ExternCrypt, protect, const Data &,
                                 const Data &, const Data &, const Data &,
                                 const Data &, const Data &, const Data &,
                                 const Data &, const Data &);
BM_REGISTER_EXTERN_W_NAME_METHOD(ext_crypt, ExternCrypt, validate, const Data &,
                                 const Data &, const Data &, const Data &,
                                 const Data &, const Data &, Data &, Data &);
