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
  explicit PnaNicHandler(PnaNic *sw)
    : nic_(sw) { }

  void mirroring_session_add(const int32_t mirror_id,
                             const MirroringSessionConfig &config) {
    bm::Logger::get()->trace("mirroring_session_add");
    PnaNic::MirroringSessionConfig config_ = {}; // value-initialization
    // if (config.__isset.port) {
    //   config_.egress_port = config.port;
    //   config_.egress_port_valid = true;
    // }
    if (config.__isset.mgid) {
      config_.mgid = config.mgid;
      config_.mgid_valid = true;
    }
    nic_->mirroring_add_session(mirror_id, config_);
  }

  void mirroring_session_delete(const int32_t mirror_id) {
    bm::Logger::get()->trace("mirroring_session_delete");
    auto session_found = nic_->mirroring_delete_session(mirror_id);
    if (!session_found) {
      InvalidMirroringOperation e;
      e.code = MirroringOperationErrorCode::SESSION_NOT_FOUND;
      throw e;
    }
  }

  void mirroring_session_get(MirroringSessionConfig& _return,
                             const int32_t mirror_id) {
    bm::Logger::get()->trace("mirroring_session_get");
    PnaNic::MirroringSessionConfig config;
    if (nic_->mirroring_get_session(mirror_id, &config)) {
      // if (config.egress_port_valid) _return.__set_port(config.egress_port);
      if (config.mgid_valid) _return.__set_mgid(config.mgid);
    } else {
      InvalidMirroringOperation e;
      e.code = MirroringOperationErrorCode::SESSION_NOT_FOUND;
      throw e;
    }
  }

  // int32_t set_egress_queue_depth(const int32_t port_num,
  //                                const int32_t depth_pkts) {
  //   bm::Logger::get()->trace("set_egress_queue_depth");
  //   return nic_->set_egress_queue_depth(port_num,
  //                                          static_cast<uint32_t>(depth_pkts));
  // }

  // int32_t set_all_egress_queue_depths(const int32_t depth_pkts) {
  //   bm::Logger::get()->trace("set_all_egress_queue_depths");
  //   return nic_->set_all_egress_queue_depths(
  //       static_cast<uint32_t>(depth_pkts));
  // }

  // int32_t set_egress_queue_rate(const int32_t port_num,
  //                               const int64_t rate_pps) {
  //   bm::Logger::get()->trace("set_egress_queue_rate");
  //   return nic_->set_egress_queue_rate(port_num,
  //                                         static_cast<uint64_t>(rate_pps));
  // }

  // int32_t set_all_egress_queue_rates(const int64_t rate_pps) {
  //   bm::Logger::get()->trace("set_all_egress_queue_rates");
  //   return nic_->set_all_egress_queue_rates(static_cast<uint64_t>(rate_pps));
  // }

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

stdcxx::shared_ptr<PnaNicIf> get_handler(PnaNic *sw) {
  return stdcxx::shared_ptr<PnaNicHandler>(new PnaNicHandler(sw));
}

}  // namespace pnic_runtime