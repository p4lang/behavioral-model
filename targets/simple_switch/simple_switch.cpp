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

#include <bm/bm_sim/_assert.h>
#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/tables.h>
#include <bm/bm_sim/logger.h>

#include <unistd.h>

// aes stuff
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// needed for externs
#include <bm/bm_sim/extern.h>

#include <condition_variable>
#include <deque>
#include <iostream>
#include <fstream>
#include <mutex>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>

#include "simple_switch.h"
#include "register_access.h"

namespace {

struct hash_ex {
  uint32_t operator()(const char *buf, size_t s) const {
    const uint32_t p = 16777619;
    uint32_t hash = 2166136261;

    for (size_t i = 0; i < s; i++)
      hash = (hash ^ buf[i]) * p;

    hash += hash << 13;
    hash ^= hash >> 7;
    hash += hash << 3;
    hash ^= hash >> 17;
    hash += hash << 5;
    return static_cast<uint32_t>(hash);
  }
};

struct bmv2_hash {
  uint64_t operator()(const char *buf, size_t s) const {
    return bm::hash::xxh64(buf, s);
  }
};

}  // namespace

// if REGISTER_HASH calls placed in the anonymous namespace, some compiler can
// give an unused variable warning
REGISTER_HASH(hash_ex);
REGISTER_HASH(bmv2_hash);

// using namespace bm;
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

namespace bm {
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
}  // namespace bm

extern int import_primitives(SimpleSwitch *simple_switch);

packet_id_t SimpleSwitch::packet_id = 0;

class SimpleSwitch::MirroringSessions {
 public:
  bool add_session(mirror_id_t mirror_id,
                   const MirroringSessionConfig &config) {
    Lock lock(mutex);
    if (0 <= mirror_id && mirror_id <= RegisterAccess::MAX_MIRROR_SESSION_ID) {
      sessions_map[mirror_id] = config;
      return true;
    } else {
      bm::Logger::get()->error("mirror_id out of range. No session added.");
      return false;
    }
  }

  bool delete_session(mirror_id_t mirror_id) {
    Lock lock(mutex);
    if (0 <= mirror_id && mirror_id <= RegisterAccess::MAX_MIRROR_SESSION_ID) {
      return sessions_map.erase(mirror_id) == 1;
    } else {
      bm::Logger::get()->error("mirror_id out of range. No session deleted.");
      return false;
    }
  }

  bool get_session(mirror_id_t mirror_id,
                   MirroringSessionConfig *config) const {
    Lock lock(mutex);
    auto it = sessions_map.find(mirror_id);
    if (it == sessions_map.end()) return false;
    *config = it->second;
    return true;
  }

 private:
  using Mutex = std::mutex;
  using Lock = std::lock_guard<Mutex>;

  mutable std::mutex mutex;
  std::unordered_map<mirror_id_t, MirroringSessionConfig> sessions_map;
};

// Arbitrates which packets are processed by the ingress thread. Resubmit and
// recirculate packets go to a high priority queue, while normal pakcets go to a
// low priority queue. We assume that starvation is not going to be a problem.
// Resubmit packets are dropped if the queue is full in order to make sure the
// ingress thread cannot deadlock. We do the same for recirculate packets even
// though the same argument does not apply for them. Enqueueing normal packets
// is blocking (back pressure is applied to the interface).
class SimpleSwitch::InputBuffer {
 public:
  enum class PacketType {
    NORMAL,
    RESUBMIT,
    RECIRCULATE,
    SENTINEL  // signal for the ingress thread to terminate
  };

  InputBuffer(size_t capacity_hi, size_t capacity_lo)
      : capacity_hi(capacity_hi), capacity_lo(capacity_lo) { }

  int push_front(PacketType packet_type, std::unique_ptr<Packet> &&item) {
    switch (packet_type) {
      case PacketType::NORMAL:
        return push_front(&queue_lo, capacity_lo, &cvar_can_push_lo,
                          std::move(item), true);
      case PacketType::RESUBMIT:
      case PacketType::RECIRCULATE:
        return push_front(&queue_hi, capacity_hi, &cvar_can_push_hi,
                          std::move(item), false);
      case PacketType::SENTINEL:
        return push_front(&queue_hi, capacity_hi, &cvar_can_push_hi,
                          std::move(item), true);
    }
    _BM_UNREACHABLE("Unreachable statement");
    return 0;
  }

  void pop_back(std::unique_ptr<Packet> *pItem) {
    Lock lock(mutex);
    cvar_can_pop.wait(
        lock, [this] { return (queue_hi.size() + queue_lo.size()) > 0; });
    // give higher priority to resubmit/recirculate queue
    if (queue_hi.size() > 0) {
      *pItem = std::move(queue_hi.back());
      queue_hi.pop_back();
      lock.unlock();
      cvar_can_push_hi.notify_one();
    } else {
      *pItem = std::move(queue_lo.back());
      queue_lo.pop_back();
      lock.unlock();
      cvar_can_push_lo.notify_one();
    }
  }

 private:
  using Mutex = std::mutex;
  using Lock = std::unique_lock<Mutex>;
  using QueueImpl = std::deque<std::unique_ptr<Packet> >;

  int push_front(QueueImpl *queue, size_t capacity,
                 std::condition_variable *cvar,
                 std::unique_ptr<Packet> &&item, bool blocking) {
    Lock lock(mutex);
    while (queue->size() == capacity) {
      if (!blocking) return 0;
      cvar->wait(lock);
    }
    queue->push_front(std::move(item));
    lock.unlock();
    cvar_can_pop.notify_one();
    return 1;
  }

  mutable std::mutex mutex;
  mutable std::condition_variable cvar_can_push_hi;
  mutable std::condition_variable cvar_can_push_lo;
  mutable std::condition_variable cvar_can_pop;
  size_t capacity_hi;
  size_t capacity_lo;
  QueueImpl queue_hi;
  QueueImpl queue_lo;
};

SimpleSwitch::SimpleSwitch(bool enable_swap, port_t drop_port)
  : Switch(enable_swap),
    drop_port(drop_port),
    input_buffer(new InputBuffer(
        1024 /* normal capacity */, 1024 /* resubmit/recirc capacity */)),
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    egress_buffers(nb_egress_threads,
                   64, EgressThreadMapper(nb_egress_threads),
                   SSWITCH_PRIORITY_QUEUEING_NB_QUEUES),
#else
    egress_buffers(nb_egress_threads,
                   64, EgressThreadMapper(nb_egress_threads)),
#endif
    output_buffer(128),
    // cannot use std::bind because of a clang bug
    // https://stackoverflow.com/questions/32030141/is-this-incorrect-use-of-stdbind-or-a-compiler-bug
    my_transmit_fn([this](port_t port_num, packet_id_t pkt_id,
                          const char *buffer, int len) {
        _BM_UNUSED(pkt_id);
        this->transmit_fn(port_num, buffer, len);
    }),
    pre(new McSimplePreLAG()),
    start(clock::now()),
    mirroring_sessions(new MirroringSessions()) {
  add_component<McSimplePreLAG>(pre);

  add_required_field("standard_metadata", "ingress_port");
  add_required_field("standard_metadata", "packet_length");
  add_required_field("standard_metadata", "instance_type");
  add_required_field("standard_metadata", "egress_spec");
  add_required_field("standard_metadata", "egress_port");

  force_arith_header("standard_metadata");
  force_arith_header("queueing_metadata");
  force_arith_header("intrinsic_metadata");

  import_primitives(this);
}

int
SimpleSwitch::receive_(port_t port_num, const char *buffer, int len) {
  // this is a good place to call this, because blocking this thread will not
  // block the processing of existing packet instances, which is a requirement
  if (do_swap() == 0) {
    check_queueing_metadata();
  }

  // we limit the packet buffer to original size + 512 bytes, which means we
  // cannot add more than 512 bytes of header data to the packet, which should
  // be more than enough
  auto packet = new_packet_ptr(port_num, packet_id++, len,
                               bm::PacketBuffer(len + 512, buffer, len));

  BMELOG(packet_in, *packet);

  PHV *phv = packet->get_phv();
  // many current P4 programs assume this
  // it is also part of the original P4 spec
  phv->reset_metadata();
  RegisterAccess::clear_all(packet.get());

  // setting standard metadata

  phv->get_field("standard_metadata.ingress_port").set(port_num);
  // using packet register 0 to store length, this register will be updated for
  // each add_header / remove_header primitive call
  packet->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, len);
  phv->get_field("standard_metadata.packet_length").set(len);
  Field &f_instance_type = phv->get_field("standard_metadata.instance_type");
  f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);

  if (phv->has_field("intrinsic_metadata.ingress_global_timestamp")) {
    phv->get_field("intrinsic_metadata.ingress_global_timestamp")
        .set(get_ts().count());
  }

  input_buffer->push_front(
      InputBuffer::PacketType::NORMAL, std::move(packet));
  return 0;
}

void
SimpleSwitch::start_and_return_() {
  check_queueing_metadata();

  threads_.push_back(std::thread(&SimpleSwitch::ingress_thread, this));
  for (size_t i = 0; i < nb_egress_threads; i++) {
    threads_.push_back(std::thread(&SimpleSwitch::egress_thread, this, i));
  }
  threads_.push_back(std::thread(&SimpleSwitch::transmit_thread, this));
}

SimpleSwitch::~SimpleSwitch() {
  input_buffer->push_front(
      InputBuffer::PacketType::SENTINEL, nullptr);
  for (size_t i = 0; i < nb_egress_threads; i++) {
    // The push_front call is called inside a while loop because there is no
    // guarantee that the sentinel was enqueued otherwise. It should not be an
    // issue because at this stage the ingress thread has been sent a signal to
    // stop, and only egress clones can be sent to the buffer.
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    while (egress_buffers.push_front(i, 0, nullptr) == 0) continue;
#else
    while (egress_buffers.push_front(i, nullptr) == 0) continue;
#endif
  }
  output_buffer.push_front(nullptr);
  for (auto& thread_ : threads_) {
    thread_.join();
  }
}

void
SimpleSwitch::reset_target_state_() {
  bm::Logger::get()->debug("Resetting simple_switch target-specific state");
  get_component<McSimplePreLAG>()->reset_state();
}

bool
SimpleSwitch::mirroring_add_session(mirror_id_t mirror_id,
                                    const MirroringSessionConfig &config) {
  return mirroring_sessions->add_session(mirror_id, config);
}

bool
SimpleSwitch::mirroring_delete_session(mirror_id_t mirror_id) {
  return mirroring_sessions->delete_session(mirror_id);
}

bool
SimpleSwitch::mirroring_get_session(mirror_id_t mirror_id,
                                    MirroringSessionConfig *config) const {
  return mirroring_sessions->get_session(mirror_id, config);
}

int
SimpleSwitch::set_egress_queue_depth(size_t port, const size_t depth_pkts) {
  egress_buffers.set_capacity(port, depth_pkts);
  return 0;
}

int
SimpleSwitch::set_all_egress_queue_depths(const size_t depth_pkts) {
  egress_buffers.set_capacity_for_all(depth_pkts);
  return 0;
}

int
SimpleSwitch::set_egress_queue_rate(size_t port, const uint64_t rate_pps) {
  egress_buffers.set_rate(port, rate_pps);
  return 0;
}

int
SimpleSwitch::set_all_egress_queue_rates(const uint64_t rate_pps) {
  egress_buffers.set_rate_for_all(rate_pps);
  return 0;
}

uint64_t
SimpleSwitch::get_time_elapsed_us() const {
  return get_ts().count();
}

uint64_t
SimpleSwitch::get_time_since_epoch_us() const {
  auto tp = clock::now();
  return duration_cast<ts_res>(tp.time_since_epoch()).count();
}

void
SimpleSwitch::set_transmit_fn(TransmitFn fn) {
  my_transmit_fn = std::move(fn);
}

void
SimpleSwitch::transmit_thread() {
  while (1) {
    std::unique_ptr<Packet> packet;
    output_buffer.pop_back(&packet);
    if (packet == nullptr) break;
    BMELOG(packet_out, *packet);
    BMLOG_DEBUG_PKT(*packet, "Transmitting packet of size {} out of port {}",
                    packet->get_data_size(), packet->get_egress_port());
    my_transmit_fn(packet->get_egress_port(), packet->get_packet_id(),
                   packet->data(), packet->get_data_size());
  }
}

ts_res
SimpleSwitch::get_ts() const {
  return duration_cast<ts_res>(clock::now() - start);
}

void
SimpleSwitch::enqueue(port_t egress_port, std::unique_ptr<Packet> &&packet) {
    packet->set_egress_port(egress_port);

    PHV *phv = packet->get_phv();

    if (with_queueing_metadata) {
      phv->get_field("queueing_metadata.enq_timestamp").set(get_ts().count());
      phv->get_field("queueing_metadata.enq_qdepth")
          .set(egress_buffers.size(egress_port));
    }

#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    size_t priority = phv->has_field(SSWITCH_PRIORITY_QUEUEING_SRC) ?
        phv->get_field(SSWITCH_PRIORITY_QUEUEING_SRC).get<size_t>() : 0u;
    if (priority >= SSWITCH_PRIORITY_QUEUEING_NB_QUEUES) {
      bm::Logger::get()->error("Priority out of range, dropping packet");
      return;
    }
    egress_buffers.push_front(
        egress_port, SSWITCH_PRIORITY_QUEUEING_NB_QUEUES - 1 - priority,
        std::move(packet));
#else
    egress_buffers.push_front(egress_port, std::move(packet));
#endif
}

// used for ingress cloning, resubmit
void
SimpleSwitch::copy_field_list_and_set_type(
    const std::unique_ptr<Packet> &packet,
    const std::unique_ptr<Packet> &packet_copy,
    PktInstanceType copy_type, p4object_id_t field_list_id) {
  PHV *phv_copy = packet_copy->get_phv();
  phv_copy->reset_metadata();
  FieldList *field_list = this->get_field_list(field_list_id);
  field_list->copy_fields_between_phvs(phv_copy, packet->get_phv());
  phv_copy->get_field("standard_metadata.instance_type").set(copy_type);
}

void
SimpleSwitch::check_queueing_metadata() {
  // TODO(antonin): add qid in required fields
  bool enq_timestamp_e = field_exists("queueing_metadata", "enq_timestamp");
  bool enq_qdepth_e = field_exists("queueing_metadata", "enq_qdepth");
  bool deq_timedelta_e = field_exists("queueing_metadata", "deq_timedelta");
  bool deq_qdepth_e = field_exists("queueing_metadata", "deq_qdepth");
  if (enq_timestamp_e || enq_qdepth_e || deq_timedelta_e || deq_qdepth_e) {
    if (enq_timestamp_e && enq_qdepth_e && deq_timedelta_e && deq_qdepth_e)
      with_queueing_metadata = true;
    else
      bm::Logger::get()->warn(
          "Your JSON input defines some but not all queueing metadata fields");
  }
}

void
SimpleSwitch::multicast(Packet *packet, unsigned int mgid) {
  auto *phv = packet->get_phv();
  auto &f_rid = phv->get_field("intrinsic_metadata.egress_rid");
  const auto pre_out = pre->replicate({mgid});
  auto packet_size =
      packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);
  for (const auto &out : pre_out) {
    auto egress_port = out.egress_port;
    BMLOG_DEBUG_PKT(*packet, "Replicating packet on port {}", egress_port);
    f_rid.set(out.rid);
    std::unique_ptr<Packet> packet_copy = packet->clone_with_phv_ptr();
    RegisterAccess::clear_all(packet_copy.get());
    packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                              packet_size);
    enqueue(egress_port, std::move(packet_copy));
  }
}

void
SimpleSwitch::ingress_thread() {
  PHV *phv;

  while (1) {
    std::unique_ptr<Packet> packet;
    input_buffer->pop_back(&packet);
    if (packet == nullptr) break;

    // TODO(antonin): only update these if swapping actually happened?
    Parser *parser = this->get_parser("parser");
    Pipeline *ingress_mau = this->get_pipeline("ingress");

    phv = packet->get_phv();

    port_t ingress_port = packet->get_ingress_port();
    (void) ingress_port;
    BMLOG_DEBUG_PKT(*packet, "Processing packet received on port {}",
                    ingress_port);

    auto ingress_packet_size =
        packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);

    /* This looks like it comes out of the blue. However this is needed for
       ingress cloning. The parser updates the buffer state (pops the parsed
       headers) to make the deparser's job easier (the same buffer is
       re-used). But for ingress cloning, the original packet is needed. This
       kind of looks hacky though. Maybe a better solution would be to have the
       parser leave the buffer unchanged, and move the pop logic to the
       deparser. TODO? */
    const Packet::buffer_state_t packet_in_state = packet->save_buffer_state();
    parser->parse(packet.get());

    if (phv->has_field("standard_metadata.parser_error")) {
      phv->get_field("standard_metadata.parser_error").set(
          packet->get_error_code().get());
    }

    if (phv->has_field("standard_metadata.checksum_error")) {
      phv->get_field("standard_metadata.checksum_error").set(
           packet->get_checksum_error() ? 1 : 0);
    }

    ingress_mau->apply(packet.get());

    packet->reset_exit();

    Field &f_egress_spec = phv->get_field("standard_metadata.egress_spec");
    port_t egress_spec = f_egress_spec.get_uint();

    auto clone_mirror_session_id =
        RegisterAccess::get_clone_mirror_session_id(packet.get());
    auto clone_field_list = RegisterAccess::get_clone_field_list(packet.get());

    int learn_id = RegisterAccess::get_lf_field_list(packet.get());
    unsigned int mgid = 0u;

    // detect mcast support, if this is true we assume that other fields needed
    // for mcast are also defined
    if (phv->has_field("intrinsic_metadata.mcast_grp")) {
      Field &f_mgid = phv->get_field("intrinsic_metadata.mcast_grp");
      mgid = f_mgid.get_uint();
    }

    // INGRESS CLONING
    if (clone_mirror_session_id) {
      BMLOG_DEBUG_PKT(*packet, "Cloning packet at ingress");
      RegisterAccess::set_clone_mirror_session_id(packet.get(), 0);
      RegisterAccess::set_clone_field_list(packet.get(), 0);
      MirroringSessionConfig config;
      // Extract the part of clone_mirror_session_id that contains the
      // actual session id.
      clone_mirror_session_id &= RegisterAccess::MIRROR_SESSION_ID_MASK;
      bool is_session_configured = mirroring_get_session(
          static_cast<mirror_id_t>(clone_mirror_session_id), &config);
      if (is_session_configured) {
        const Packet::buffer_state_t packet_out_state =
            packet->save_buffer_state();
        packet->restore_buffer_state(packet_in_state);
        p4object_id_t field_list_id = clone_field_list;
        std::unique_ptr<Packet> packet_copy = packet->clone_no_phv_ptr();
        RegisterAccess::clear_all(packet_copy.get());
        packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                                  ingress_packet_size);
        // we need to parse again
        // the alternative would be to pay the (huge) price of PHV copy for
        // every ingress packet
        parser->parse(packet_copy.get());
        copy_field_list_and_set_type(packet, packet_copy,
                                     PKT_INSTANCE_TYPE_INGRESS_CLONE,
                                     field_list_id);
        if (config.mgid_valid) {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to MGID {}", config.mgid);
          multicast(packet_copy.get(), config.mgid);
        }
        if (config.egress_port_valid) {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to egress port {}",
                          config.egress_port);
          enqueue(config.egress_port, std::move(packet_copy));
        }
        packet->restore_buffer_state(packet_out_state);
      }
    }

    // LEARNING
    if (learn_id > 0) {
      get_learn_engine()->learn(learn_id, *packet.get());
    }

    // RESUBMIT
    auto resubmit_flag = RegisterAccess::get_resubmit_flag(packet.get());
    if (resubmit_flag) {
      BMLOG_DEBUG_PKT(*packet, "Resubmitting packet");
      // get the packet ready for being parsed again at the beginning of
      // ingress
      packet->restore_buffer_state(packet_in_state);
      p4object_id_t field_list_id = resubmit_flag;
      RegisterAccess::set_resubmit_flag(packet.get(), 0);
      // TODO(antonin): a copy is not needed here, but I don't yet have an
      // optimized way of doing this
      std::unique_ptr<Packet> packet_copy = packet->clone_no_phv_ptr();
      copy_field_list_and_set_type(packet, packet_copy,
                                   PKT_INSTANCE_TYPE_RESUBMIT,
                                   field_list_id);
      RegisterAccess::clear_all(packet_copy.get());
      input_buffer->push_front(
          InputBuffer::PacketType::RESUBMIT, std::move(packet_copy));
      continue;
    }

    // MULTICAST
    if (mgid != 0) {
      BMLOG_DEBUG_PKT(*packet, "Multicast requested for packet");
      auto &f_instance_type = phv->get_field("standard_metadata.instance_type");
      f_instance_type.set(PKT_INSTANCE_TYPE_REPLICATION);
      multicast(packet.get(), mgid);
      // when doing multicast, we discard the original packet
      continue;
    }

    port_t egress_port = egress_spec;
    BMLOG_DEBUG_PKT(*packet, "Egress port is {}", egress_port);

    if (egress_port == drop_port) {  // drop packet
      BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of ingress");
      continue;
    }
    auto &f_instance_type = phv->get_field("standard_metadata.instance_type");
    f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);

    enqueue(egress_port, std::move(packet));
  }
}

void
SimpleSwitch::egress_thread(size_t worker_id) {
  PHV *phv;

  while (1) {
    std::unique_ptr<Packet> packet;
    size_t port;
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    size_t priority;
    egress_buffers.pop_back(worker_id, &port, &priority, &packet);
#else
    egress_buffers.pop_back(worker_id, &port, &packet);
#endif
    if (packet == nullptr) break;

    Deparser *deparser = this->get_deparser("deparser");
    Pipeline *egress_mau = this->get_pipeline("egress");

    phv = packet->get_phv();

    if (phv->has_field("intrinsic_metadata.egress_global_timestamp")) {
      phv->get_field("intrinsic_metadata.egress_global_timestamp")
          .set(get_ts().count());
    }

    if (with_queueing_metadata) {
      auto enq_timestamp =
          phv->get_field("queueing_metadata.enq_timestamp").get<ts_res::rep>();
      phv->get_field("queueing_metadata.deq_timedelta").set(
          get_ts().count() - enq_timestamp);
      phv->get_field("queueing_metadata.deq_qdepth").set(
          egress_buffers.size(port));
      if (phv->has_field("queueing_metadata.qid")) {
        auto &qid_f = phv->get_field("queueing_metadata.qid");
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
        qid_f.set(SSWITCH_PRIORITY_QUEUEING_NB_QUEUES - 1 - priority);
#else
        qid_f.set(0);
#endif
      }
    }

    phv->get_field("standard_metadata.egress_port").set(port);

    Field &f_egress_spec = phv->get_field("standard_metadata.egress_spec");
    f_egress_spec.set(0);

    phv->get_field("standard_metadata.packet_length").set(
        packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX));

    egress_mau->apply(packet.get());

    auto clone_mirror_session_id =
        RegisterAccess::get_clone_mirror_session_id(packet.get());
    auto clone_field_list = RegisterAccess::get_clone_field_list(packet.get());

    // EGRESS CLONING
    if (clone_mirror_session_id) {
      BMLOG_DEBUG_PKT(*packet, "Cloning packet at egress");
      RegisterAccess::set_clone_mirror_session_id(packet.get(), 0);
      RegisterAccess::set_clone_field_list(packet.get(), 0);
      MirroringSessionConfig config;
      // Extract the part of clone_mirror_session_id that contains the
      // actual session id.
      clone_mirror_session_id &= RegisterAccess::MIRROR_SESSION_ID_MASK;
      bool is_session_configured = mirroring_get_session(
          static_cast<mirror_id_t>(clone_mirror_session_id), &config);
      if (is_session_configured) {
        p4object_id_t field_list_id = clone_field_list;
        std::unique_ptr<Packet> packet_copy =
            packet->clone_with_phv_reset_metadata_ptr();
        PHV *phv_copy = packet_copy->get_phv();
        FieldList *field_list = this->get_field_list(field_list_id);
        field_list->copy_fields_between_phvs(phv_copy, phv);
        phv_copy->get_field("standard_metadata.instance_type")
            .set(PKT_INSTANCE_TYPE_EGRESS_CLONE);
        if (config.mgid_valid) {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to MGID {}", config.mgid);
          multicast(packet_copy.get(), config.mgid);
        }
        if (config.egress_port_valid) {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to egress port {}",
                          config.egress_port);
          RegisterAccess::clear_all(packet_copy.get());
          enqueue(config.egress_port, std::move(packet_copy));
        }
      }
    }

    // TODO(antonin): should not be done like this in egress pipeline
    port_t egress_spec = f_egress_spec.get_uint();
    if (egress_spec == drop_port) {  // drop packet
      BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of egress");
      continue;
    }

    deparser->deparse(packet.get());

    // RECIRCULATE
    auto recirculate_flag = RegisterAccess::get_recirculate_flag(packet.get());
    if (recirculate_flag) {
      BMLOG_DEBUG_PKT(*packet, "Recirculating packet");
      p4object_id_t field_list_id = recirculate_flag;
      RegisterAccess::set_recirculate_flag(packet.get(), 0);
      FieldList *field_list = this->get_field_list(field_list_id);
      // TODO(antonin): just like for resubmit, there is no need for a copy
      // here, but it is more convenient for this first prototype
      std::unique_ptr<Packet> packet_copy = packet->clone_no_phv_ptr();
      PHV *phv_copy = packet_copy->get_phv();
      phv_copy->reset_metadata();
      field_list->copy_fields_between_phvs(phv_copy, phv);
      phv_copy->get_field("standard_metadata.instance_type")
          .set(PKT_INSTANCE_TYPE_RECIRC);
      size_t packet_size = packet_copy->get_data_size();
      RegisterAccess::clear_all(packet_copy.get());
      packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                                packet_size);
      phv_copy->get_field("standard_metadata.packet_length").set(packet_size);
      // TODO(antonin): really it may be better to create a new packet here or
      // to fold this functionality into the Packet class?
      packet_copy->set_ingress_length(packet_size);
      input_buffer->push_front(
          InputBuffer::PacketType::RECIRCULATE, std::move(packet_copy));
      continue;
    }

    output_buffer.push_front(std::move(packet));
  }
}
