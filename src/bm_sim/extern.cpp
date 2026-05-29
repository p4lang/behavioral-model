// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/extern.h>

#include <string>

namespace bm {

ExternFactoryMap *
ExternFactoryMap::get_instance() {
  static ExternFactoryMap instance;
  return &instance;
}

int
ExternFactoryMap::register_extern_type(const char *extern_type_name,
                                       ExternFactoryFn fn) {
  const std::string str_name = std::string(extern_type_name);
  auto it = factory_map.find(str_name);
  if (it != factory_map.end()) return 0;
  factory_map[str_name] = std::move(fn);
  return 1;
}

std::unique_ptr<ExternType>
ExternFactoryMap::get_extern_instance(
    const std::string &extern_type_name) const {
  auto it = factory_map.find(extern_type_name);
  if (it == factory_map.end()) return nullptr;
  return it->second();
}

void
ExternType::_set_p4objects(P4Objects *p4objects) {
  this->p4objects = p4objects;
}

void
ExternType::_set_name_and_id(const std::string &name, p4object_id_t id) {
  this->name = name;
  this->id = id;
}

}  // namespace bm
