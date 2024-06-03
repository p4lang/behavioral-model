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

#ifndef PNA_NIC_PNA_NIC_H_
#define PNA_NIC_PNA_NIC_H_

#include <bm/bm_sim/queue.h>
#include <bm/bm_sim/queueing.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/switch.h>
#include <bm/bm_sim/event_logger.h>
#include <bm/bm_sim/simple_pre_lag.h>

#include <memory>
#include <chrono>
#include <thread>
#include <vector>
#include <functional>

// TODO(antonin)
// experimental support for priority queueing
// to enable it, uncomment this flag
// you can also choose the field from which the priority value will be read, as
// well as the number of priority queues per port
// PRIORITY 0 IS THE LOWEST PRIORITY
// #define NNIC_PRIORITY_QUEUEING_ON

// #ifdef NNIC_PRIORITY_QUEUEING_ON
// #define NNIC_PRIORITY_QUEUEING_NB_QUEUES 8
// #define NNIC_PRIORITY_QUEUEING_SRC "intrinsic_metadata.priority"
// #endif

using ts_res = std::chrono::microseconds;
using std::chrono::duration_cast;
using ticks = std::chrono::nanoseconds;

namespace bm {

namespace pna {

class PnaNic : public Switch {
 public:
  using mirror_id_t = int;

  using TransmitFn = std::function<void(port_t, packet_id_t,
                                        const char *, int)>;

  struct MirroringSessionConfig {
    unsigned int mgid;
    bool mgid_valid;
  };

 private:
  using clock = std::chrono::high_resolution_clock;

 public:
  // by default, swapping is off
  explicit PnaNic(bool enable_swap = false);

  ~PnaNic();

  int receive_(port_t port_num, const char *buffer, int len) override;

  void start_and_return_() override;

  void reset_target_state_() override;

  bool mirroring_add_session(mirror_id_t mirror_id,
                             const MirroringSessionConfig &config);
  bool mirroring_delete_session(mirror_id_t mirror_id);
  bool mirroring_get_session(mirror_id_t mirror_id,
                             MirroringSessionConfig *config) const;

  int mirroring_mapping_add(mirror_id_t mirror_id, port_t egress_port) {
    mirroring_map[mirror_id] = egress_port;
    return 0;
  }
  int mirroring_mapping_delete(mirror_id_t mirror_id) {
    return mirroring_map.erase(mirror_id);
  }
  bool mirroring_mapping_get(mirror_id_t mirror_id, port_t *port) const {
    return get_mirroring_mapping(mirror_id, port);
  }

  // returns the number of microseconds elapsed since the nic started
  uint64_t get_time_elapsed_us() const;

  // returns the number of microseconds elasped since the clock's epoch
  uint64_t get_time_since_epoch_us() const;

  // returns the packet id of most recently received packet. Not thread-safe.
  static packet_id_t get_packet_id() {
    return (packet_id-1);
  }

  void set_transmit_fn(TransmitFn fn);

  // TODO(derek): override RuntimeInterface methods not yet supported
  //              by pna_nic and log an error msg / return error code

 private:
  static packet_id_t packet_id;

  class MirroringSessions;

  enum PktInstanceType {
    FROM_NET_PORT,
    FROM_NET_LOOPEDBACK,
    FROM_NET_RECIRCULATED,
    FROM_HOST,
    FROM_HOST_LOOPEDBACK,
    FROM_HOST_RECIRCULATED,
  };

  enum PktDirection {
    NET_TO_HOST,
    HOST_TO_NET,
  };

 private:
  void main_thread();
  void transmit_thread();

  bool get_mirroring_mapping(mirror_id_t mirror_id, port_t *port) const {
    const auto it = mirroring_map.find(mirror_id);
    if (it != mirroring_map.end()) {
      *port = it->second;
      return true;
    }
    return false;
  }

  ts_res get_ts() const;

  // // TODO(antonin): switch to pass by value?
  // void enqueue(port_t egress_port, std::unique_ptr<Packet> &&packet);

  void check_queueing_metadata();

 private:
  std::vector<std::thread> threads_;
  Queue<std::unique_ptr<Packet> > input_buffer;
  Queue<std::unique_ptr<Packet> > output_buffer;
  TransmitFn my_transmit_fn;
  std::shared_ptr<McSimplePreLAG> pre;
  clock::time_point start;
  std::unordered_map<mirror_id_t, port_t> mirroring_map;
  std::unique_ptr<MirroringSessions> mirroring_sessions;
  bool with_queueing_metadata{false};
};

}  // namespace bm::pna

}  // namespace bm

#endif  // PNA_NIC_PNA_NIC_H_
