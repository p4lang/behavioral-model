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

#ifndef SIMPLE_SWITCH_GRPC_SWITCH_RUNNER_H_
#define SIMPLE_SWITCH_GRPC_SWITCH_RUNNER_H_

#include <bm/bm_sim/dev_mgr.h>
#include <bm/bm_sim/simple_pre.h>

#include <grpcpp/server.h>

#include <memory>
#include <string>

class SimpleSwitch;

namespace bm {

class OptionsParser;

}  // namespace bm

namespace sswitch_grpc {

class SysrepoDriver;

class DataplaneInterfaceServiceImpl;

struct SSLOptions {
  std::string pem_root_certs;
  std::string pem_private_key;
  std::string pem_cert_chain;
  bool with_client_auth;
};

class SimpleSwitchGrpcRunner {
 public:
  static constexpr bm::DevMgrIface::port_t default_drop_port = 511;
  static constexpr size_t default_nb_queues_per_port = 1;
  static constexpr int default_mgid_table_size =
      bm::McSimplePre::DEFAULT_MGID_TABLE_SIZE;
  static constexpr int default_l1_max_entries =
      bm::McSimplePre::DEFAULT_L1_MAX_ENTRIES;
  static constexpr int default_l2_max_entries =
      bm::McSimplePre::DEFAULT_L2_MAX_ENTRIES;

  // there is no real need for a singleton here, except for the fact that we use
  // PIGrpcServerRunAddr, ... which uses static state
  static SimpleSwitchGrpcRunner &get_instance(
      bool enable_swap = false,
      std::string grpc_server_addr = "0.0.0.0:9559",
      bm::DevMgrIface::port_t cpu_port = 0,
      std::string dp_grpc_server_addr = "",
      bm::DevMgrIface::port_t drop_port = default_drop_port,
      std::shared_ptr<SSLOptions> ssl_options = nullptr,
      size_t nb_queues_per_port = default_nb_queues_per_port,
      int mgid_table_size = default_mgid_table_size,
      int l1_max_entries = default_l1_max_entries,
      int l2_max_entries = default_l2_max_entries) {
    static SimpleSwitchGrpcRunner instance(
        enable_swap, grpc_server_addr, cpu_port, dp_grpc_server_addr,
        drop_port, ssl_options, nb_queues_per_port,
        mgid_table_size, l1_max_entries, l2_max_entries);
    return instance;
  }

  int init_and_start(const bm::OptionsParser &parser);
  void wait();
  void shutdown();
  int get_dp_grpc_server_port() {
    return dp_grpc_server_port;
  }
  void block_until_all_packets_processed();
  bool is_dp_service_active();

 private:
  SimpleSwitchGrpcRunner(bool enable_swap = false,
                         std::string grpc_server_addr = "0.0.0.0:9559",
                         bm::DevMgrIface::port_t cpu_port = 0,
                         std::string dp_grpc_server_addr = "",
                         bm::DevMgrIface::port_t drop_port = default_drop_port,
                         std::shared_ptr<SSLOptions> ssl_options = nullptr,
                         size_t nb_queues_per_port =
                             default_nb_queues_per_port,
                         int mgid_table_size = default_mgid_table_size,
                         int l1_max_entries = default_l1_max_entries,
                         int l2_max_entries = default_l2_max_entries);
  ~SimpleSwitchGrpcRunner();

  void port_status_cb(bm::DevMgrIface::port_t port,
                      const bm::DevMgrIface::PortStatus port_status);

  std::unique_ptr<SimpleSwitch> simple_switch;
  std::string grpc_server_addr;
  bm::DevMgrIface::port_t cpu_port;
  std::string dp_grpc_server_addr;
  int dp_grpc_server_port;
  DataplaneInterfaceServiceImpl *dp_service;
  std::unique_ptr<grpc::Server> dp_grpc_server;
#ifdef WITH_SYSREPO
  std::unique_ptr<SysrepoDriver> sysrepo_driver;
#endif  // WITH_SYSREPO
  std::shared_ptr<SSLOptions> ssl_options;
};

}  // namespace sswitch_grpc

#endif  // SIMPLE_SWITCH_GRPC_SWITCH_RUNNER_H_
