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

#include "bm_sim/stateful.h"

namespace bm {

void
RegisterArray::reset_state() {
  auto lock = UniqueLock();
  for (auto &r : registers) {
    r.set(0);
  }
}


void
RegisterSync::add_register_array(RegisterArray *register_array) {
  if (register_arrays.insert(register_array).second)
    locks.push_back(UniqueLock(register_array->m_mutex, std::defer_lock));
}

}  // namespace bm
