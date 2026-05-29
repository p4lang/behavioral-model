/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef BM_BM_SIM_ENUMS_H_
#define BM_BM_SIM_ENUMS_H_

#include <string>
#include <unordered_map>

namespace bm {

// for this class, "name" refers to an enum entry's full name (i.e. enum name +
// "." + entry name), "enum_name" refers to an enum's name, and "entry_name"
// refers to an entry's name within an enum declaration.
class EnumMap {
 public:
  using type_t = int;

  // returns an enum entry value from its full name; will thow a
  // std::out_of_range exception if does not exist
  type_t from_name(const std::string &name) const;
  // returns an enum entry full name from the enum name and the entry value;
  // will throw a std::out_of_range exception if does not exist
  const std::string &to_name(const std::string &enum_name, type_t v) const;

  // returns true iff the enum does not already exist
  bool add_enum(const std::string &enum_name);
  // returns true iff the enum exists and the entry name / value have not been
  // taken yet
  bool add_entry(const std::string &enum_name, const std::string &entry_name,
                 type_t v);

 private:
  using EntryMap = std::unordered_map<type_t, std::string>;

  std::unordered_map<std::string, type_t> map_name_to_v{};
  std::unordered_map<std::string, EntryMap> map_enum_name_to_entries{};
};

}  // namespace bm

#endif  // BM_BM_SIM_ENUMS_H_
