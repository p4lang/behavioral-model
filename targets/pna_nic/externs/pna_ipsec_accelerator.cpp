/* Copyright 2024 Marvell Technology, Inc.
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
 * Rupesh Chiluka (rchiluka@marvell.com)
 *
 */

#include "pna_ipsec_accelerator.h"

namespace bm {

namespace pna {

void PNA_IpsecAccelerator::init() {
    _is_enabled = false;
}

void PNA_IpsecAccelerator::decrypt() {
}

void PNA_IpsecAccelerator::encrypt() {
}

void PNA_IpsecAccelerator::set_sa_index(const Data &sa_index) {
    _sa_index = sa_index.get<uint32_t>();
}

void PNA_IpsecAccelerator::enable() {
    _is_enabled = true;
}

void PNA_IpsecAccelerator::disable() {
    _is_enabled = false;
}

BM_REGISTER_EXTERN_W_NAME(ipsec_accelerator, PNA_IpsecAccelerator);
BM_REGISTER_EXTERN_W_NAME_METHOD(ipsec_accelerator, PNA_IpsecAccelerator, set_sa_index, const Data
 &);
BM_REGISTER_EXTERN_W_NAME_METHOD(ipsec_accelerator, PNA_IpsecAccelerator, enable);
BM_REGISTER_EXTERN_W_NAME_METHOD(ipsec_accelerator, PNA_IpsecAccelerator, disable);

}  // namespace bm::pna

}  // namespace bm

int import_ipsec_accelerator() {
    return 0;
}
