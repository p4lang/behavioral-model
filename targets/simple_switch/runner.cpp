/* Copyright 2018-present Barefoot Networks, Inc.
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

#include <bm/bm_sim/_assert.h>
#include <bm/bm_sim/logger.h>

#ifdef WITH_PI
#include <bm/PI/pi.h>
#endif

#include <bm/simple_switch/runner.h>

#ifdef WITH_PI
#include <PI/pi.h>
#include <PI/target/pi_imp.h>
#include <PI/target/pi_learn_imp.h>
#endif

#include "simple_switch.h"

namespace bm {

namespace sswitch {

#ifdef WITH_PI
// P4Runtime supports sending notifications to the client which are
// "traditionally" sent using nanomsg PUBSUB messages: table entry idle time
// notifications & learning notifications. simple_switch "captures" these
// notifications by providing a custom TransportIface implementation to the
// Switch base class. At the moment we capture all notifications (include port
// oper status notifications), but we only process (i.e. send through P4Runtime)
// learning notifications. This should not be a problem as users of
// simple_switch usually disable nanomsg anyway.
class NotificationsCapture : public bm::TransportIface {
 public:
  explicit NotificationsCapture(bm::SwitchWContexts *sw)
      : sw(sw) { }

 private:
  static constexpr size_t hdr_size = 32u;

  using Lock = std::lock_guard<std::mutex>;

  struct LEA_hdr_t {
    char sub_topic[4];
    uint64_t switch_id;
    uint32_t cxt_id;
    int list_id;
    uint64_t buffer_id;
    unsigned int num_samples;
  } __attribute__((packed));

  struct AGE_hdr_t {
    char sub_topic[4];
    uint64_t switch_id;
    uint32_t cxt_id;
    uint64_t buffer_id;
    int table_id;
    unsigned int num_entries;
  } __attribute__((packed));

  struct PRT_hdr_t {
    char sub_topic[4];
    uint64_t switch_id;
    unsigned int num_statuses;
    char _padding[16];
  } __attribute__((packed));

  struct SWP_hdr_t {
    char sub_topic[4];
    uint64_t switch_id;
    uint32_t cxt_id;
    int status;
    char _padding[12];
  } __attribute__((packed));

  static_assert(sizeof(LEA_hdr_t) == hdr_size,
                "Invalid size for notification header");
  static_assert(sizeof(AGE_hdr_t) == hdr_size,
                "Invalid size for notification header");
  static_assert(sizeof(PRT_hdr_t) == hdr_size,
                "Invalid size for notification header");
  static_assert(sizeof(SWP_hdr_t) == hdr_size,
                "Invalid size for notification header");

  int send_generic(const std::string &msg) const {
    if (msg.size() < hdr_size) return 1;
    // all notification headers have size 32 bytes, padded at the end if needed
    std::aligned_storage<hdr_size>::type storage;
    std::memcpy(&storage, msg.data(), sizeof(storage));
    const char *data = msg.data() + hdr_size;
    Lock lock(mutex);
    if (!memcmp("SWP|", msg.data(), 4)) {
      handle_SWP(reinterpret_cast<const SWP_hdr_t *>(&storage));
    } else if (!memcmp("LEA|", msg.data(), 4)) {
      handle_LEA(reinterpret_cast<const LEA_hdr_t *>(&storage),
                 data, msg.size() - hdr_size);
    } else if (!memcmp("AGE|", msg.data(), 4)) {
      handle_AGE(reinterpret_cast<const AGE_hdr_t *>(&storage),
                 data, msg.size() - hdr_size);
    }
    return 0;
  }

  // we use Swap notifications to ensure that learning & ageing notificaitons
  // are not sent to PI / P4Runtime during the config swap process, which is a
  // requirement of the p4lang P4Runtime implementation.
  void handle_SWP(const SWP_hdr_t *hdr) const {
    if (hdr->cxt_id != 0) {
      return;
    }
    enum SwapStatus {
      NEW_CONFIG_LOADED = 0,
      SWAP_REQUESTED = 1,
      SWAP_COMPLETED = 2,
      SWAP_CANCELLED = 3
    };
    if (static_cast<SwapStatus>(hdr->status) == NEW_CONFIG_LOADED) {
      ongoing_swap = true;
    } else if (static_cast<SwapStatus>(hdr->status) == SWAP_COMPLETED ||
               static_cast<SwapStatus>(hdr->status) == SWAP_CANCELLED) {
      ongoing_swap = false;
    }
  }

  void handle_LEA(const LEA_hdr_t *hdr, const char *data, size_t size) const {
    // do not send notifications to PI if there is an ongoing swap; this is a
    // requirement of the p4lang P4Runtime implementation.
    if (ongoing_swap) {
      BMLOG_TRACE(
          "Ignoring LEA notification because of ongoing dataplane swap");
      return;
    }
    const auto *learn_engine = sw->get_learn_engine(0);
    std::string list_name;
    if (learn_engine->list_get_name_from_id(hdr->list_id, &list_name) !=
        bm::LearnEngineIface::LearnErrorCode::SUCCESS) {
      bm::Logger::get()->error(
          "Ignoring LEA notification with unknown learn list id {}",
          hdr->list_id);
      return;
    }
    auto *p4info = pi_get_device_p4info(hdr->switch_id);
    if (p4info == nullptr) {
      bm::Logger::get()->error(
          "Ignoring LEA notification for device {} which has no p4info",
          hdr->switch_id);
      return;
    }
    pi_p4_id_t pi_id = pi_p4info_digest_id_from_name(p4info, list_name.c_str());
    if (pi_id == PI_INVALID_ID) {
      bm::Logger::get()->error(
          "Ignoring LEA notification whose name '{}' cannot be found in p4info",
          list_name);
      return;
    }
    size_t data_size = pi_p4info_digest_data_size(p4info, pi_id);
    if (data_size != size / hdr->num_samples) {
      bm::Logger::get()->error(
          "Dropping LEA notification with name '{}' because of unexpected "
          "digest size", list_name);
      return;
    }
    // Arguably this part of the code should be in PI/src/pi_learn_imp.cpp,
    // along with the pi_learn_msg_done implementation (which releases the
    // memory allocated here).
    pi_learn_msg_t *pi_msg = new pi_learn_msg_t;
    pi_msg->dev_tgt.dev_id = hdr->switch_id;
    pi_msg->dev_tgt.dev_pipe_mask = hdr->cxt_id;
    pi_msg->learn_id = pi_id;
    pi_msg->msg_id = hdr->buffer_id;
    pi_msg->num_entries = hdr->num_samples;
    pi_msg->entry_size = data_size;
    pi_msg->entries = new char[size];
    std::memcpy(pi_msg->entries, data, size);
    pi_learn_new_msg(pi_msg);
  }

  void handle_AGE(const AGE_hdr_t *hdr, const char *data, size_t size) const {
    (void) size;
    // do not send notifications to PI if there is an ongoing swap; this is a
    // requirement of the p4lang P4Runtime implementation.
    if (ongoing_swap) {
      BMLOG_TRACE(
          "Ignoring AGE notification because of ongoing dataplane swap");
      return;
    }

    const auto *ageing_monitor = sw->get_ageing_monitor(0);
    auto table_name = ageing_monitor->get_table_name_from_id(hdr->table_id);
    if (table_name == "") {
      bm::Logger::get()->error(
          "Ignoring AGE notification with unknown table id {}", hdr->table_id);
      return;
    }
    auto *p4info = pi_get_device_p4info(hdr->switch_id);
    if (p4info == nullptr) {
      bm::Logger::get()->error(
          "Ignoring AGE notification for device {} which has no p4info",
          hdr->switch_id);
      return;
    }
    pi_p4_id_t pi_id = pi_p4info_table_id_from_name(p4info, table_name.c_str());
    if (pi_id == PI_INVALID_ID) {
      bm::Logger::get()->error(
          "Ignoring AGE notification for table whose name '{}' "
          "cannot be found in p4info", table_name);
      return;
    }

    auto *handles = reinterpret_cast<const uint32_t *>(data);
    for (unsigned int i = 0; i < hdr->num_entries; i++) {
      bm::pi::table_idle_timeout_notify(
          hdr->switch_id, pi_id, static_cast<pi_entry_handle_t>(handles[i]));
    }
  }

  int open_() override {
    return 0;
  }

  int send_(const std::string &msg) const override {
    return send_generic(msg);
  }

  int send_(const char *msg, int len) const override {
    return send_generic(std::string(msg, len));
  }

  int send_msgs_(
      const std::initializer_list<std::string> &msgs) const override {
    std::string buf;
    for (const auto &msg : msgs) buf.append(msg);
    return send_generic(buf);
  }

  int send_msgs_(const std::initializer_list<MsgBuf> &msgs) const override {
    // TODO(antonin): since this is the method which is actually used by the
    // bm_sim library when generating notifications, it may make sense to
    // optimize the implementation for this case...
    std::string buf;
    for (const auto &msg : msgs) buf.append(msg.buf, msg.len);
    return send_generic(buf);
  }

  mutable std::mutex mutex{};
  mutable bool ongoing_swap{false};
  bm::SwitchWContexts *sw;
};
#endif

/* static */
constexpr uint32_t SimpleSwitchRunner::default_drop_port;

SimpleSwitchRunner::SimpleSwitchRunner(uint32_t cpu_port, uint32_t drop_port)
    : cpu_port(cpu_port),
      simple_switch(new SimpleSwitch(true /* enable_swap */, drop_port)) { }

SimpleSwitchRunner::~SimpleSwitchRunner() = default;

int SimpleSwitchRunner::init_and_start(const bm::OptionsParser &parser) {
  std::shared_ptr<bm::TransportIface> my_transport;
#ifdef WITH_PI
  my_transport = std::make_shared<NotificationsCapture>(
      simple_switch.get());
#endif
  int status = simple_switch->init_from_options_parser(
      parser, std::move(my_transport), nullptr);
  if (status != 0) return status;

#ifdef WITH_PI
  auto transmit_fn = [this](bm::DevMgrIface::port_t port_num,
                            packet_id_t pkt_id, const char *buf, int len) {
    (void)pkt_id;
    if (cpu_port > 0 && port_num == cpu_port) {
      BMLOG_DEBUG("Transmitting packet-in");
      auto status = pi_packetin_receive(simple_switch->get_device_id(),
                                        buf, static_cast<size_t>(len));
      if (status != PI_STATUS_SUCCESS)
        bm::Logger::get()->error("Error when transmitting packet-in");
    } else {
      simple_switch->transmit_fn(port_num, buf, len);
    }
  };
  simple_switch->set_transmit_fn(transmit_fn);

  bm::pi::register_switch(simple_switch.get(), cpu_port);
#endif

  simple_switch->start_and_return();

  return 0;
}

device_id_t SimpleSwitchRunner::get_device_id() const {
  return simple_switch->get_device_id();
}

DevMgr *SimpleSwitchRunner::get_dev_mgr() {
  return simple_switch.get();
}

}  // namespace sswitch

}  // namespace bm
