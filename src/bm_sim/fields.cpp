// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/fields.h>
#include <bm/bm_sim/headers.h>
#include <bm/bm_sim/logger.h>

#include <algorithm>  // for std::swap
#include "extract.h"

namespace bm {

bool Field::warn_on_invalid_hdr_read = false;
bool Field::ret_zero_on_invalid_hdr_read = false;
bool Field::handle_invalid_hdr_read = false;

Bignum Field::zero{0};

Field::Field(int nbits, Header *parent_hdr, bool arith_flag, bool is_signed,
             bool hidden, bool VL, bool is_saturating)
    : nbits(nbits), nbytes((nbits + 7) / 8), bytes(nbytes),
      parent_hdr(parent_hdr),
      is_signed(is_signed), hidden(hidden), VL(VL),
      is_saturating(is_saturating) {
  arith = arith_flag;
  // TODO(antonin) ?
  // should I only do that for arith fields ?
  mask <<= nbits; mask -= 1;
  if (is_signed) {
    assert(nbits > 1);
    max <<= (nbits - 1); max -= 1;
    min <<= (nbits - 1); min *= -1;
  } else {
    max = mask;
    min = 0;
  }
}

void
Field::reserve_VL(size_t max_bytes) {
  if (VL) bytes.reserve(max_bytes);
}

void
Field::swap_values(Field *other) {
  // do not swap arith!
  std::swap(get_nc_value(), other->get_nc_value());
  std::swap(bytes, other->bytes);
  if (VL) {
    std::swap(nbits, other->nbits);
    std::swap(nbytes, other->nbytes);
    std::swap(mask, other->mask);
    assert(is_signed == other->is_signed);
    assert(is_saturating == other->is_saturating);
    std::swap(max, other->max);
    std::swap(min, other->min);
  }
}

int
Field::extract(const char *data, int hdr_offset) {
  extract::generic_extract(data, hdr_offset, nbits, bytes.data());

  if (arith) sync_value();

  return nbits;
}

int
Field::extract_VL(const char *data, int hdr_offset, int computed_nbits) {
  nbits = computed_nbits;
  nbytes = (nbits + 7) / 8;
  mask = 1; mask <<= nbits; mask -= 1;
  bytes.resize(nbytes);
  if (is_signed) {
    assert(nbits > 1);
    max <<= (nbits - 1); max -= 1;
    min <<= (nbits - 1); min *= -1;
  } else {
    max = mask;
    min = 0;
  }
  return Field::extract(data, hdr_offset);
}

int
Field::deparse(char *data, int hdr_offset) const {
  // this does not work for empty variable-length fields, as we assert in the
  // ByteContainer's [] operator. The right thing to do would probably be to add
  // a at() method to ByteContainer and not perform any check in [].
  // extract::generic_deparse(&bytes[0], nbits, data, hdr_offset);
  extract::generic_deparse(bytes.data(), nbits, data, hdr_offset);
  return nbits;
}

void
Field::assign_VL(const Field &src) {
  assert(VL);
  nbits = src.nbits;
  nbytes = src.nbytes;
  bytes.resize(nbytes);
  mask = src.mask;
  max = src.max;
  min = src.min;
  set(src);
  parent_hdr->recompute_nbytes_packet();
}

void
Field::reset_VL() {
  assert(VL);
  nbits = 0;
  nbytes = 0;
  mask = 1;
  if (is_signed) {
    max = 1;
    min = 1;
  }
}

void
Field::copy_value(const Field &src) {
  // it's important to have a way of copying a field value without the
  // packet_id pointer. This is used by PHV::copy_headers().
  set_value(src.get_value());
  bytes = src.bytes;
  if (VL) {
    nbits = src.nbits;
    nbytes = src.nbytes;
    mask = src.mask;
    min = src.min;
    max = src.max;
  }
}

bool
Field::is_valid() const {
  // FIXME: Consider using the written_to flag in the evalutation. Would
  // need to make sure this is cleared whenever the header is marked invalid.

  // Hidden fields assumed always valid. Needed for header validity bit.
  return hidden || !parent_hdr || parent_hdr->is_valid();
}

const Bignum &
Field::get_value() const {
  if (handle_invalid_hdr_read && !is_valid()) {
    if (warn_on_invalid_hdr_read) {
      assert(parent_hdr);
      Logger::get()->warn(
          "Reading an invalid field (header: {}, field offset: {})",
          parent_hdr->get_name(), parent_hdr->get_field_offset(this));
    }
    if (ret_zero_on_invalid_hdr_read) {
      return zero;
    }
  }
  return Data::get_value();
}

}  // namespace bm
