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

//! @file fields.h

#ifndef BM_BM_SIM_FIELDS_H_
#define BM_BM_SIM_FIELDS_H_

#include <bm/config.h>

#include <algorithm>  // for std::copy

#include <cassert>

#include "data.h"
#include "bytecontainer.h"
#include "bignum.h"
#include "debugger.h"

namespace bm {

class Header;

//! Field objects are used to represent P4 fields. Each Field instance belongs
//! to a Header instance. When defining your own target, you will have to
//! manipulate Field objects to set and access the target's intrinsic metadata.
//! Most of the interesting methods for a target designer are inherited from
//! Data.
class Field : public Data {
 public:
  // Data() is called automatically
  // I wanted to have a separate class for signed fields, inheriting from
  // Field. Unfortunately that would require adding an extra level of
  // indirection in Header (for the field vector), so I am sticking to this for
  // now.
  explicit Field(int nbits, Header *parent_hdr, bool arith_flag = true,
                 bool is_signed = false, bool hidden = false, bool VL = false,
                 bool is_saturating = false);

  // to avoid dynamic resizing of the Bytecontainer, which would invalide field
  // references
  void reserve_VL(size_t max_bytes);

  // Overload set? Make it more generic (arbitary length) ?
  // It is probably only going to be used by the checksum engine anyway...
  void set_bytes(const char *src_bytes, int len) {
    assert(len == nbytes);
    std::copy(src_bytes, src_bytes + len, bytes.begin());
    if (arith) sync_value();
  }

  void sync_value() {
    bignum::import_bytes(&value, bytes.data(), nbytes);
    if (is_signed && bignum::test_bit(value, nbits - 1)) {
      bignum::clear_bit(&value, nbits - 1);
      value += min;
    }
    written_to = true;
    // TODO(antonin): should notifications be disabled for hidden fields?
    DEBUGGER_NOTIFY_UPDATE(*packet_id, my_id, bytes.data(), nbits);
  }

  //! Return the byte representation of this field. Note that this returns a
  //! reference to a byte container, which is only valid as long as the Field
  //! instance is alive.
  const ByteContainer &get_bytes() const {
    return bytes;
  }

  //! Get the number of bytes occupied by this field, not based on its layout in
  //! the packet header, but assuming a byte boundary alignment for the most
  //! significant bit. `nbytes = (nbits + 7) / 8`
  int get_nbytes() const {
    return nbytes;
  }

  //! Get the number of bits occupied by this field in the packet header
  int get_nbits() const {
    return nbits;
  }

  void set_arith(bool arith_flag) { arith = arith_flag; }

  bool get_arith_flag() const { return arith; }

  void export_bytes() override {
    std::fill(bytes.begin(), bytes.end(), 0);  // very important !

    if (is_saturating) {
      if (value < min) value = min;
      else if (value > max) value = max;
    }

    if (!is_signed) {
      // is this efficient enough?
      value &= mask;
      bignum::export_bytes(bytes.data(), nbytes, value);
    } else {
      if (value < min || value > mask) {
        value &= mask;
        if (value > max) value -= (mask + 1);
      }
      if (value >= 0) {
        bignum::export_bytes(bytes.data(), nbytes, value);
      } else {
        // e.g. if width is 8 and value is -127 (1000 0001), subtracting min
        // (-128) one time gives us 1, a second time gives us 129, 129 has a
        // bignum representation of 1000 0001, which is what we wanted
        bignum::export_bytes(bytes.data(), nbytes, value - min - min);
      }
    }
    written_to = true;
    DEBUGGER_NOTIFY_UPDATE(*packet_id, my_id, bytes.data(), nbits);
  }

  // useful for header stacks
  void swap_values(Field *other);

  // returns the number of bits extracted
  int extract(const char *data, int hdr_offset);

  int extract_VL(const char *data, int hdr_offset, int computed_nbits);

  // returns the number of bits deparsed
  int deparse(char *data, int hdr_offset) const;

  void assign_VL(const Field &src);

  void reset_VL();

#ifdef BM_DEBUG_ON
  void set_id(uint64_t id) { my_id = id; }
  void set_packet_id(const Debugger::PacketId *id) { packet_id = id; }
#else
  void set_id(uint64_t) { }
  void set_packet_id(const Debugger::PacketId *) { }
#endif

  // it's important to have a way of copying a field value without the packet_id
  // pointer. This is used by PHV::copy_headers().
  void copy_value(const Field &src);

  bool is_hidden() const {
    return hidden;
  }

  bool is_VL() const {
    return VL;
  }

  //! Set the value of the written_to flag for the field. This flag can be
  //! queried at any time using get_written_to() and is used to check whether
  //! the field has been modified since written_to was last set to `false`.
  void set_written_to(bool v) {
    written_to = v;
  }

  //! Get the value of the written_to flag. See set_written_to() for more
  //! information.
  bool get_written_to() const {
    return written_to;
  }

 private:
  int nbits;
  int nbytes;
  ByteContainer bytes;
  Header *parent_hdr;
  bool is_signed{false};
  bool hidden{false};
  bool VL{false};
  bool is_saturating{false};
  bool written_to{false};  // used to keep track of whether a field was modified
  Bignum mask{1};
  Bignum max{1};
  Bignum min{1};
#ifdef BM_DEBUG_ON
  uint64_t my_id{};
  const Debugger::PacketId *packet_id{&Debugger::dummy_PacketId};
#endif
};

}  // namespace bm

#endif  // BM_BM_SIM_FIELDS_H_
