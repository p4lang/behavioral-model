/* Copyright 2017 Cisco Systems, Inc.
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
 * Andy Fingerhut (jafinger@cisco.com)
 *
 */

#ifndef BM_BM_SIM_SOURCE_INFO_H_
#define BM_BM_SIM_SOURCE_INFO_H_

//! @file source_info.h
//! Stores source location information about some objects, as read from
//! the JSON file produced by the compiler.

#include <string>
#include "jsoncpp/json.h"

namespace bm {

class SourceInfo {
 public:
  SourceInfo()
    : filename(""), line(0), column(0), source_fragment("") { }
  SourceInfo(std::string filename, unsigned line, unsigned column,
             std::string source_fragment)
    : filename(filename),
      line(line),
      column(column),
      source_fragment(source_fragment) { }

  static SourceInfo *newFromJson(const Json::Value &cfg_source_info) {
    std::string filename = "";
    unsigned line = 0;
    unsigned column = 0;
    std::string source_fragment = "";

    if (cfg_source_info.isNull()) {
      return nullptr;
    }
    if (!cfg_source_info["filename"].isNull()) {
      filename = cfg_source_info["filename"].asString();
    }
    if (!cfg_source_info["line"].isNull()) {
      line = cfg_source_info["line"].asInt();
    }
    if (!cfg_source_info["column"].isNull()) {
      column = cfg_source_info["column"].asInt();
    }
    if (!cfg_source_info["source_fragment"].isNull()) {
      source_fragment = cfg_source_info["source_fragment"].asString();
    }
    return new SourceInfo(filename, line, column, source_fragment);
  }

  std::string toString() const {
    std::stringstream result;
    result << filename << "(" << line << ":" << column << ")";
    return result.str();
  }

  std::string get_source_fragment() const { return source_fragment; }

 private:
  std::string filename;
  unsigned line;
  unsigned column;
  std::string source_fragment;
};

}  // namespace bm

#endif  // BM_BM_SIM_SOURCE_INFO_H_
