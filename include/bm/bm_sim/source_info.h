/*
 * Copyright 2017 Cisco Systems, Inc.
 * SPDX-FileCopyrightText: 2017 Cisco Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Andy Fingerhut (jafinger@cisco.com)
 *
 */

#ifndef BM_BM_SIM_SOURCE_INFO_H_
#define BM_BM_SIM_SOURCE_INFO_H_

//! @file source_info.h
//! Stores source location information about some objects, as read from
//! the JSON file produced by the compiler.

#include <string>

namespace bm {

class SourceInfo {
 public:
  SourceInfo(std::string filename, unsigned int line, unsigned int column,
             std::string source_fragment)
    : filename(filename), line(line), column(column),
      source_fragment(source_fragment) {
    init_to_string();
  }

  std::string get_filename() const { return filename; }
  unsigned int get_line() const { return line; }
  unsigned int get_column() const { return column; }
  std::string get_source_fragment() const { return source_fragment; }
  std::string to_string() const { return string_representation; }

 private:
  std::string filename;
  unsigned int line;
  unsigned int column;
  std::string source_fragment;
  std::string string_representation;

  void init_to_string();
};

}  // namespace bm

#endif  // BM_BM_SIM_SOURCE_INFO_H_
