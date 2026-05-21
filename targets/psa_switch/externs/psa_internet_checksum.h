/*
 * Copyright 2021 SYRMIA LLC
 * SPDX-FileCopyrightText: 2021 SYRMIA LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Dusan Krdzic (dusan.krdzic@syrmia.com)
 *
 */


#ifndef PSA_SWITCH_PSA_INTERNETCHECKSUM_H_
#define PSA_SWITCH_PSA_INTERNETCHECKSUM_H_

#include <bm/bm_sim/extern.h>

namespace bm {

namespace psa {

class PSA_InternetChecksum : public bm::ExternType {
 public:

    BM_EXTERN_ATTRIBUTES {
}

    void init() override;

    void get(Field &dst) const;

    void get_verify(Field &dst, Field &equOp) const;

    void clear();

    void add(const std::vector<Field> &fields);

    void subtract(const std::vector<Field> &fields);

    void get_state(Field &dst) const;

    void set_state(const Data &src);

 private:
    uint16_t sum;

};

}  // namespace bm::psa

}  // namespace bm
#endif
