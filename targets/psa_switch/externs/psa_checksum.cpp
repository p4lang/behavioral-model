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
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/calculations.h>

namespace {

static const unsigned char hex_digits[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

uint8_t convertHexStrToU8(std::string hex) {
  int a;
  std::istringstream(hex) >> std::hex >> a;
  return static_cast<uint8_t>(a);
}

std::string prepareDataForHash(bm::Data &input) {
  std::string hex_ascii;
  std::string hex_hex;
  uint8_t k = 0;
  const uint8_t base = 16;
  while (input != 0) {
    hex_ascii += hex_digits[input % base];
    input.divide(input, base);
    k++;
    if (k % 2 == 0) {
      std::reverse(hex_ascii.begin(), hex_ascii.end());
      uint8_t c = convertHexStrToU8(hex_ascii);
      hex_hex += c;
      hex_ascii.clear();
      k=0;
    } else if (k % 2 == 1 && input == 0) {
      uint8_t c = convertHexStrToU8(hex_ascii);
      hex_hex += c;
      hex_ascii.clear();
    }
  }
  std::reverse(hex_hex.begin(), hex_hex.end());
  return hex_hex;
}

struct psa_crc16 {
  uint16_t operator()(const char *buf, size_t s) const {
    return bm::hash::CRC16(buf, s);
  }
};

struct psa_crc32 {
  uint32_t operator()(const char *buf, size_t s) const {
    return bm::hash::CRC32(buf, s);
  }
};

struct psa_crc16_custom {
  uint16_t operator()(const char *buf, size_t s) const {
    return bm::hash::CRC16_CUSTOM(buf, s);
  }
};

struct psa_crc32_custom {
  uint32_t operator()(const char *buf, size_t s) const {
    return bm::hash::CRC32_CUSTOM(buf, s);
  }
};

struct psa_identity {
  uint64_t operator()(const char *buf, size_t s) const {
    return bm::hash::IDENTITY(buf, s);
  }
};

} // namespace

REGISTER_HASH(psa_crc16);
REGISTER_HASH(psa_crc32);
REGISTER_HASH(psa_crc16_custom);
REGISTER_HASH(psa_crc32_custom);
REGISTER_HASH(psa_identity);

namespace bm {

namespace psa {

void
PSA_Checksum::init() {
  this->clear();
}

void
PSA_Checksum::get(Field& dst) const {
  dst.set(internal.get<uint64_t>());
}

void
PSA_Checksum::get_verify(Field& dst, Field& equOp) const {
  dst.set(equOp.get<uint64_t>() == internal.get<uint64_t>());
}

void
PSA_Checksum::clear() {
  internal.set(0);
}

void
PSA_Checksum::update(const std::vector<Field> fields) {
  Data input;
  input.set(0);
  uint16_t current_bits_offset = 0;

  // Vector fields has separate field values as its elements.
  // They need to be concatenated to one single data which represents value from packet.
  for(int i = fields.size() - 1 ; i >= 0 ; i--) {
    Data shift_value;
    shift_value.shift_left(Data(fields.at(i).get<uint64_t>()), current_bits_offset);
    input.add(input, shift_value);
    current_bits_offset += fields.at(i).get_nbits();
  }

  // Data input is in decimal format and it needs to be converted to hexadecimal,
  // because value in packet is in hexadecimal.
  // Hash algorithms process the data in chunks of bytes (chars).
  // If the hex value from input is "4F", it semantically means 0x4F.
  // If "4F" is directly passed to hash algorithm, it will process it as 0x34 0x46.
  // So, it is important to convert the hex value 0x4F to ASCII char which is 'O'.
  // Then the hash algorithm will process it as 0x4F.
  std::string hex = prepareDataForHash(input);

  uint64_t cksum = this->compute(hex.data(), hex.size());
  internal.set(cksum);
}

uint64_t PSA_Checksum::compute(const char *buffer, size_t s) {
  if (hash == "CRC16") {
    psa_crc16 algo;
    return algo(buffer, s);
  } if (hash == "CRC16_CUSTOM") {
    psa_crc16_custom algo;
    return algo(buffer, s);
  } else if (hash == "CRC32") {
    psa_crc32 algo;
    return algo(buffer, s);
  } else if (hash == "CRC32_CUSTOM") {
    psa_crc32_custom algo;
    return algo(buffer, s);
  } else if (hash == "IDENTITY") {
    psa_identity algo;
    return algo(buffer, s);
  }
  return 0;
}

BM_REGISTER_EXTERN_W_NAME(Checksum, PSA_Checksum);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum, update, const std::vector<Field>);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum, get, Field &);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum, get_verify, Field &, Field &);
BM_REGISTER_EXTERN_W_NAME_METHOD(Checksum, PSA_Checksum, clear);

}  // namespace bm::psa

}  // namespace bm

int import_checksums() {
  return 0;
}
