// Copyright 2024 Marvell Technology, Inc.
// SPDX-FileCopyrightText: 2024 Marvell Technology, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Rupesh Chiluka (rchiluka@marvell.com)
 *
 */

#include <bm/config.h>
#include <bm/PnaNic.h>

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>

namespace thrift_provider = apache::thrift;

#include <bm/bm_sim/switch.h>
#include <bm/bm_sim/logger.h>
#include <bm/thrift/stdcxx.h>

#include "pna_nic.h"

using namespace bm::pna;

namespace pnic_runtime {

class PnaNicHandler : virtual public PnaNicIf {
 public:
  explicit PnaNicHandler(PnaNic *nic)
    : nic_(nic) { }

  int64_t get_time_elapsed_us() {
    bm::Logger::get()->trace("get_time_elapsed_us");
    // cast from unsigned to signed
    return static_cast<int64_t>(nic_->get_time_elapsed_us());
  }

  int64_t get_time_since_epoch_us() {
    bm::Logger::get()->trace("get_time_since_epoch_us");
    // cast from unsigned to signed
    return static_cast<int64_t>(nic_->get_time_since_epoch_us());
  }

 private:
  PnaNic *nic_;
};

stdcxx::shared_ptr<PnaNicIf> get_handler(PnaNic *nic) {
  return stdcxx::shared_ptr<PnaNicHandler>(new PnaNicHandler(nic));
}

}  // namespace pnic_runtime
