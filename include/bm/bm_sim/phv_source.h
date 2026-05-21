/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef BM_BM_SIM_PHV_SOURCE_H_
#define BM_BM_SIM_PHV_SOURCE_H_

#include <memory>

#include "device_id.h"
#include "phv_forward.h"

namespace bm {

class PHVSourceIface {
 public:
  virtual ~PHVSourceIface() { }

  std::unique_ptr<PHV> get(cxt_id_t cxt);

  void release(cxt_id_t cxt, std::unique_ptr<PHV> phv);

  void set_phv_factory(cxt_id_t cxt, const PHVFactory *factory);

  size_t phvs_in_use(cxt_id_t cxt);

  static std::unique_ptr<PHVSourceIface> make_phv_source(size_t size = 1);

 private:
  virtual std::unique_ptr<PHV> get_(cxt_id_t cxt) = 0;

  virtual void release_(cxt_id_t cxt, std::unique_ptr<PHV> phv) = 0;

  virtual void set_phv_factory_(cxt_id_t cxt, const PHVFactory *factory) = 0;

  virtual size_t phvs_in_use_(cxt_id_t cxt) = 0;
};

}  // namespace bm

#endif  // BM_BM_SIM_PHV_SOURCE_H_
