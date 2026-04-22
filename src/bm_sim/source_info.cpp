// Copyright 2017 Cisco Systems, Inc.
// SPDX-FileCopyrightText: 2017 Cisco Systems, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Andy Fingerhut (jafinger@cisco.com)
 *
 */

#include <bm/bm_sim/source_info.h>
#include <sstream>

namespace bm {

void SourceInfo::init_to_string() {
  std::stringstream result;
  result << filename << "(" << line << ")";
  string_representation = result.str();
}

}  // namespace bm
