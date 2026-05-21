// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include "common.h"

#include <algorithm>  // for std::copy

namespace pibmv2 {

Buffer::Buffer(size_t capacity) {
  data_.reserve(capacity);
}

char *
Buffer::extend(size_t s) {
  if (s == 0) return nullptr;
  const auto size = data_.size();
  data_.resize(size + s);
  return &data_[size];
}

char *
Buffer::copy() const {
  char *res = new char[data_.size()];
  std::copy(data_.begin(), data_.end(), res);
  return res;
}

char *
Buffer::data() {
  return data_.data();
}

size_t
Buffer::size() const {
  return data_.size();
}

}  // namespace pibmv2
