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

#ifndef BM_BM_SIM_DEVICE_ID_H_
#define BM_BM_SIM_DEVICE_ID_H_

namespace bm {

// s_* for serialized value format (e.g. notifications)
using device_id_t = uint64_t;
using s_device_id_t = device_id_t;
using cxt_id_t = uint32_t;
using s_cxt_id_t = cxt_id_t;

}  // namespace bm

#endif  // BM_BM_SIM_DEVICE_ID_H_
