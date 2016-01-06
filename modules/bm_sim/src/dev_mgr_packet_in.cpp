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

#include <nanomsg/pair.h>

#include <atomic>
#include <thread>
#include <mutex>
#include <string>
#include <unordered_map>

#include "bm_sim/dev_mgr.h"
#include "bm_sim/logger.h"
#include "bm_sim/nn.h"

// private implementation

// Implementation which uses a nanomsg PAIR socket to receive / send packets
// TODO(antonin): moved lower-level NN code to separate class ?
class PacketInDevMgrImp : public DevMgrIface {
 public:
  explicit PacketInDevMgrImp(const std::string &addr,
                             bool enforce_ports = false)
      : addr(addr), s(AF_SP, NN_PAIR), enforce_ports(enforce_ports) {
    s.bind(addr.c_str());
    int rcv_timeout_ms = 100;
    s.setsockopt(NN_SOL_SOCKET, NN_RCVTIMEO,
                 &rcv_timeout_ms, sizeof(rcv_timeout_ms));

    p_monitor = PortMonitorIface::make_passive();
  }

 private:
  ~PacketInDevMgrImp() override {
    if (started) {
      stop_receive_thread = true;
      receive_thread.join();
    }
  }

  ReturnCode port_add_(const std::string &iface_name, port_t port_num,
                       const char *in_pcap, const char *out_pcap) override {
    // TODO(antonin): do we want to allow this on top of IPC messages?
    (void) iface_name;
    (void) port_num;
    (void) in_pcap;
    (void) out_pcap;
    Logger::get()->warn("When using packet in, port_add is done "
                        "through IPC messages");
    return ReturnCode::UNSUPPORTED;
  }

  ReturnCode port_remove_(port_t port_num) override {
    // TODO(antonin): do we want to allow this on top of IPC messages?
    (void) port_num;
    Logger::get()->warn("When using packet in, port_remove is done "
                        "through IPC messages");
    return ReturnCode::UNSUPPORTED;
  }

  void transmit_fn_(int port_num, const char *buffer, int len) override;

  void start_() override {
    if (started || stop_receive_thread)
      return;
    receive_thread = std::thread(
        &PacketInDevMgrImp::receive_loop, this);
    started = true;
  }

  ReturnCode set_packet_handler_(const PacketHandler &handler, void *cookie)
      override {
    pkt_handler = handler;
    pkt_cookie = cookie;
    return ReturnCode::SUCCESS;
  }

  bool port_is_up_(port_t port) override {
    if (!enforce_ports) return true;
    const auto it = added_ports.find(port);
    return (it != added_ports.end() && it->second == PortStatus::PORT_UP);
  }

 private:
  void receive_loop();

  enum MsgType {
    MSG_TYPE_PORT_ADD = 0,
    MSG_TYPE_PORT_REMOVE,
    MSG_TYPE_PORT_SET_STATUS,
    MSG_TYPE_PACKET_IN,
    MSG_TYPE_PACKET_OUT
  };

  enum MsgPortStatus {
    MSG_PORT_STATUS_DOWN = 0,
    MSG_PORT_STATUS_UP
  };

  void do_port_add(port_t port) {
    if (!enforce_ports) return;
    auto it = added_ports.find(port);
    if (it == added_ports.end()) {
      added_ports.insert(it, std::make_pair(port, PortStatus::PORT_UP));
      p_monitor->notify(port, PortStatus::PORT_ADDED);
      p_monitor->notify(port, PortStatus::PORT_UP);
    }
  }

  void do_port_remove(port_t port) {
    if (!enforce_ports) return;
    auto it = added_ports.find(port);
    if (it != added_ports.end()) {
      added_ports.erase(it);
      p_monitor->notify(port, PortStatus::PORT_REMOVED);
    }
  }

  void do_port_set_status(port_t port, PortStatus status) {
    if (!enforce_ports) return;
    auto it = added_ports.find(port);
    if (it != added_ports.end() && it->second != status) {
      it->second = status;
      p_monitor->notify(port, status);
    }
  }

  struct packet_hdr_t {
    int type;
    int port;
    // 0 for PORT_ADD, PORT_REMOVE
    // status for PORT_SET_STATUS
    // length for PACKET_IN, PACKET_OUT
    int more;
  } __attribute__((packed));

  void handle_msg(void *msg);

 private:
  std::string addr{};
  nn::socket s;
  PacketHandler pkt_handler{};
  void *pkt_cookie{nullptr};
  std::thread receive_thread{};
  std::atomic<bool> stop_receive_thread{false};
  std::atomic<bool> started{false};
  bool enforce_ports{false};
  std::unordered_map<port_t, PortStatus> added_ports{};
};

void
PacketInDevMgrImp::transmit_fn_(int port_num,
                                const char *buffer, int len) {
  struct nn_msghdr msghdr;
  std::memset(&msghdr, 0, sizeof(msghdr));
  struct nn_iovec iov;

  packet_hdr_t packet_hdr;
  packet_hdr.type = MSG_TYPE_PACKET_OUT;
  packet_hdr.port = port_num;
  packet_hdr.more = len;

  // not sure I can do better than this here
  void *msg = nn::allocmsg(sizeof(packet_hdr) + len, 0);
  std::memcpy(msg, &packet_hdr, sizeof(packet_hdr));
  std::memcpy(static_cast<char *>(msg) + sizeof(packet_hdr), buffer, len);
  iov.iov_base = &msg;
  iov.iov_len = NN_MSG;

  msghdr.msg_iov = &iov;
  msghdr.msg_iovlen = 1;

  s.sendmsg(&msghdr, 0);
  std::cout << "packet send for port " << port_num << std::endl;
}

void
PacketInDevMgrImp::handle_msg(void *msg) {
  packet_hdr_t packet_hdr;
  std::memcpy(&packet_hdr, msg, sizeof(packet_hdr));
  switch (packet_hdr.type) {
    case MSG_TYPE_PORT_ADD:
      do_port_add(packet_hdr.port);
      break;
    case MSG_TYPE_PORT_REMOVE:
      do_port_remove(packet_hdr.port);
      break;
    case MSG_TYPE_PORT_SET_STATUS:
      switch (packet_hdr.more) {
        case MSG_PORT_STATUS_DOWN:
          do_port_set_status(packet_hdr.port, PortStatus::PORT_DOWN);
          break;
        case MSG_PORT_STATUS_UP:
          do_port_set_status(packet_hdr.port, PortStatus::PORT_UP);
          break;
        default:
          Logger::get()->error("Unknown port status requested");
          break;
      }
      break;
    case MSG_TYPE_PACKET_IN:
      if (enforce_ports) {
        auto it = added_ports.find(packet_hdr.port);
        if (it == added_ports.end() || it->second != PortStatus::PORT_UP)
          break;
      }
      if (pkt_handler) {
        char *data = static_cast<char *>(msg) + sizeof(packet_hdr);
        std::cout << "packet in received on port " << packet_hdr.port
                  << std::endl;
        pkt_handler(packet_hdr.port, data, packet_hdr.more, pkt_cookie);
      }
      break;
    case MSG_TYPE_PACKET_OUT:
      Logger::get()->error("Invalid PACKET_OUT message received");
      break;
    default:
      Logger::get()->error("Unknown message type");
      break;
  }
}

void
PacketInDevMgrImp::receive_loop() {
  struct nn_msghdr msghdr;
  struct nn_iovec iov;
  void *msg = nullptr;
  iov.iov_base = &msg;
  iov.iov_len = NN_MSG;
  std::memset(&msghdr, 0, sizeof(msghdr));
  msghdr.msg_iov = &iov;
  msghdr.msg_iovlen = 1;
  while (!stop_receive_thread) {
    int rc = s.recvmsg(&msghdr, 0);
    if (rc < 0) continue;
    assert(msg);
    handle_msg(msg);
    nn::freemsg(msg);
    msg = nullptr;
  }
}

void
DevMgr::set_dev_mgr_packet_in(const std::string &addr, bool enforce_ports) {
  assert(!pimp);
  pimp = std::unique_ptr<DevMgrIface>(
      new PacketInDevMgrImp(addr, enforce_ports));
}
