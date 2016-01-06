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

/* -*-c++-*-
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef BM_SIM_INCLUDE_BM_SIM_DEV_MGR_H_
#define BM_SIM_INCLUDE_BM_SIM_DEV_MGR_H_

#include <functional>
#include <string>

#include "bm_sim/packet_handler.h"
#include "bm_sim/port_monitor.h"

class DevMgrIface : public PacketDispatcherIface {
 public:
  typedef PortMonitorIface::port_t port_t;
  typedef PortMonitorIface::PortStatus PortStatus;
  typedef PortMonitorIface::PortStatusCb PortStatusCb;

  virtual ~DevMgrIface();

  ReturnCode port_add(const std::string &iface_name, port_t port_num,
                      const char *in_pcap, const char *out_pcap);

  ReturnCode port_remove(port_t port_num);

  // TODO(antonin): add this?
  // ReturnCode set_port_status(port_t port_num, PortStatus status);

  void transmit_fn(int port_num, const char *buffer, int len) {
    transmit_fn_(port_num, buffer, len);
  }

  // start the thread that performs packet processing
  void start();

  ReturnCode set_packet_handler(const PacketHandler &handler, void *cookie);

  bool port_is_up(port_t port_num);

  ReturnCode register_status_cb(const PortStatus &type,
                                const PortStatusCb &port_cb);

 protected:
  std::unique_ptr<PortMonitorIface> p_monitor{nullptr};

 private:
  virtual ReturnCode port_add_(const std::string &iface_name, port_t port_num,
                               const char *in_pcap, const char *out_pcap) = 0;

  virtual ReturnCode port_remove_(port_t port_num) = 0;

  virtual void transmit_fn_(int port_num, const char *buffer, int len) = 0;

  virtual void start_() = 0;

  virtual ReturnCode set_packet_handler_(const PacketHandler &handler,
                                         void *cookie) = 0;

  virtual bool port_is_up_(port_t port_num) = 0;
};

// TODO(antonin): should DevMgr and DevMgrIface somehow inherit from a common
// interface, or is it not worth the trouble?
class DevMgr : public PacketDispatcherIface {
 public:
  typedef PortMonitorIface::port_t port_t;
  typedef PortMonitorIface::PortStatus PortStatus;
  typedef PortMonitorIface::PortStatusCb PortStatusCb;

  DevMgr();

  // set_dev_* : should be called before port_add and port_remove.

  // meant for testing
  void set_dev_mgr(std::unique_ptr<DevMgrIface> my_pimp);

  void set_dev_mgr_bmi();

  // The interface names are instead interpreted as file names.
  // wait_time_in_seconds indicate how long the starting thread should
  // wait before starting to process packets.
  void set_dev_mgr_files(unsigned wait_time_in_seconds);

  // if enforce ports is set to true, packets coming in on un-registered ports
  // are dropped
  void set_dev_mgr_packet_in(const std::string &addr,
                             bool enforce_ports = false);

  ReturnCode port_add(const std::string &iface_name, port_t port_num,
                      const char *in_pcap, const char *out_pcap);

  ReturnCode port_remove(port_t port_num);

  bool port_is_up(port_t port_num);

  void transmit_fn(int port_num, const char *buffer, int len);

  ReturnCode set_packet_handler(const PacketHandler &handler, void *cookie)
      override;

  ReturnCode register_status_cb(const PortStatus &type,
                                const PortStatusCb &port_cb);

  // start the thread that performs packet processing
  void start();

  DevMgr(const DevMgr &other) = delete;
  DevMgr &operator=(const DevMgr &other) = delete;

  DevMgr(DevMgr &&other) = delete;
  DevMgr &operator=(DevMgr &&other) = delete;

 protected:
  ~DevMgr();

 private:
  // Actual implementation (private)
  std::unique_ptr<DevMgrIface> pimp{nullptr};
};

#endif  // BM_SIM_INCLUDE_BM_SIM_DEV_MGR_H_
