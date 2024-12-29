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

#ifndef PNA_NIC_PNA_IPSECACCELERATOR_H_
#define PNA_NIC_PNA_IPSECACCELERATOR_H_

#define ETH_HEADER_LENGTH     14
#define IP_HEADER_LENGTH      20
#define ESP_SPI_LENGTH        4
#define ESP_SEQ_LENGTH        4
#define NEXT_HEADER_LENGTH    2

#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/context.h>
#include <openssl/evp.h>
#include <openssl/err.h>

namespace bm {

namespace pna {

class PNA_IpsecAccelerator : public bm::ExternType {
  public:

   BM_EXTERN_ATTRIBUTES {
   }

   void reset();

   void init() override;

   void set_sa_index(const Data &sa_index);

   void enable();

   void disable();

   void cipher(std::vector<unsigned char> input, std::vector<unsigned char> &output,
                unsigned char key[16], unsigned char iv[16], int encrypt);

   void decrypt(std::string string_key);

   void encrypt(std::string key, std::string iv);

  private:
   uint32_t _sa_index;
   bool _is_enabled;
   MatchTable *sad_table;
};

}  // namespace bm::pna

}  // namespace bm

#endif // PNA_NIC_PNA_IPSECACCELERATOR_H_
