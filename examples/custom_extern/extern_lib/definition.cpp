/* Copyright 2022 P4lang Authors
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

#include <bm/bm_sim/extern.h>

// Example custom extern function.
void custom_set(bm::Data & a, const bm::Data & b) {
	a.set(b);
}
BM_REGISTER_EXTERN_FUNCTION(custom_set, bm::Data &, const bm::Data &);

// Example custom extern object.
class CustomCounter : public bm::ExternType {
 public:
  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(init_count);
  }

  void init() override {
    reset();
  }

  void reset() {
    count = init_count;
  }

  void read(bm::Data &count) const {
    count = this->count;
  }

  void increment_by(const bm::Data &amount) {
    count.set(count.get<size_t>() + amount.get<size_t>());
  }

 private:
  bm::Data init_count{0};
  bm::Data count{0};
};
BM_REGISTER_EXTERN(CustomCounter);
BM_REGISTER_EXTERN_METHOD(CustomCounter, reset);
BM_REGISTER_EXTERN_METHOD(CustomCounter, read, bm::Data &);
BM_REGISTER_EXTERN_METHOD(CustomCounter, increment_by, const bm::Data &);
