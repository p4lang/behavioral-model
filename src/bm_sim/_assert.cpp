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

#include <bm/bm_sim/_assert.h>

#include <cstdlib>
#include <iostream>

namespace bm {

void _assert(const char* expr, const char* file, int line) {
  std::cerr << "Assertion '" << expr << "' failed, file '" << file
            << "' line '" << line << "'.\n";
  std::abort();
}

void error_message(const char* error_msg, const SourceInfo* srcInfo) {
    if (srcInfo != nullptr) {
        std::cerr << error_msg << ": '" << srcInfo->get_source_fragment()
        << "' failed, file '" << srcInfo->get_filename()
        << "' line '" << srcInfo->get_line() << "'.\n";
    }
}

}  // namespace bm
