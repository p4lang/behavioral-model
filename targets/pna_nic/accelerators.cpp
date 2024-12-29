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

#include "accelerators.h"

namespace bm {

namespace pna {

Accelerators::Accelerators(Context *context) {
    ctx = context;
};

void Accelerators::apply() {
    // based on the flag (PNA output metadata), call the ipsec accelerator
    // If ( phv->get_field("pna_main_output_metadata.ipsec_accelerator").get_uint() ) {
    try {

        std::string ipsec_extern_name = std::getenv("IPSEC_EXTERN_NAME") ? 
                std::getenv("IPSEC_EXTERN_NAME") : "MainControlImpl.ipsec";

        ExternType *ipsec_extern = ctx->get_extern_instance(ipsec_extern_name).get();
        if (ipsec_extern != nullptr) {
        PNA_IpsecAccelerator *ipsec_accel = dynamic_cast<PNA_IpsecAccelerator *>(ipsec_extern);
        BMLOG_DEBUG("Applying IPSec Accelerator: {}", ipsec_accel->get_name());

        ipsec_accel->apply();
        } else {
        BMLOG_DEBUG("Couldn't access IPSec Accelerator");
        }

    }
    catch (std::exception &e) {
        BMLOG_DEBUG("IPSec Accelerator NOT Found");
    }
    // }
}

} // namespace bm

} // namespace pna
