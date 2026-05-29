// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/stateful.h>

#include <iterator>  // std::distance
#include <string>
#include <vector>

namespace bm {

Register::Register(int nbits, const RegisterArray *register_array)
    : register_array(register_array) {
  mask <<= nbits; mask -= 1;
}

void
Register::export_bytes() {
  auto &value = get_nc_value();
  value &= mask;
  register_array->notify(*this);
}

RegisterArray::RegisterArray(const std::string &name, p4object_id_t id,
                             size_t size, int bitwidth)
    : NamedP4Object(name, id), bitwidth(bitwidth) {
  registers.reserve(size);
  for (size_t i = 0; i < size; i++)
    registers.emplace_back(bitwidth, this);
}

void
RegisterArray::reset_state() {
  // we build a new vector of registers, then swap, to avoid holding the lock
  // for too long
  std::vector<Register> registers_new;
  size_t s = size();
  // TODO(antonin): is this actually better than
  // std::vector<Register> registers_new(size, Register(bitwidth)); ?
  registers_new.reserve(s);
  for (size_t i = 0; i < s; i++)
    registers_new.emplace_back(bitwidth, this);
  auto lock = UniqueLock();
  registers.swap(registers_new);
}

void
RegisterArray::register_notifier(Notifier notifier) {
  notifiers.push_back(std::move(notifier));
}

void
RegisterArray::notify(const Register &reg) const {
  for (const auto &notifier : notifiers)
    notifier(std::distance(&registers[0], &reg));
}

void
RegisterSync::add_register_array(const RegisterArray *register_array) {
  if (register_arrays.insert(register_array).second)
    mutexes.push_back(&register_array->m_mutex);
}

void
RegisterSync::merge_from(const RegisterSync &other) {
  for (auto register_array : other.register_arrays)
    add_register_array(register_array);  // takes care of duplicates
}

}  // namespace bm
