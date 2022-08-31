/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2022 University of Oxford
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

#ifndef SERVICES_SWITCH_RUNNER_H_
#define SERVICES_SWITCH_RUNNER_H_

#include <bm/bm_sim/dev_mgr.h>
#include <bm/bm_sim/switch.h>
#include <bm/grpc/ssl_options.h>

#include <grpcpp/server.h>

#include <memory>
#include <string>

namespace bm {

class OptionsParser;

}  // namespace bm

namespace switch_runner {

class SysrepoDriver;

class DataplaneInterfaceServiceImpl;

class SwitchGrpcRunner {
 public:
  static constexpr bm::DevMgrIface::port_t default_drop_port = 511;
  static constexpr size_t default_nb_queues_per_port = 1;

  // there is no real need for a singleton here, except for the fact that we use
  // PIGrpcServerRunAddr, ... which uses static state
  static SwitchGrpcRunner &get_instance(
      std::shared_ptr<bm::BaseSwitch> switch_target = nullptr,
      std::string grpc_server_addr = "0.0.0.0:9559",
      bm::DevMgrIface::port_t cpu_port = 0,
      std::string dp_grpc_server_addr = "",
      std::shared_ptr<SSLOptions> ssl_options = nullptr,
      size_t nb_queues_per_port = default_nb_queues_per_port)
  {
    static SwitchGrpcRunner instance(
        switch_target, grpc_server_addr, cpu_port, dp_grpc_server_addr,
        ssl_options, nb_queues_per_port);
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
  SwitchGrpcRunner(std::shared_ptr<bm::BaseSwitch> switch_target,
                  std::string grpc_server_addr = "0.0.0.0:9559",
                  bm::DevMgrIface::port_t cpu_port = 0,
                  std::string dp_grpc_server_addr = "",
                  std::shared_ptr<SSLOptions> ssl_options = nullptr,
                  size_t nb_queues_per_port = default_nb_queues_per_port);
  ~SwitchGrpcRunner();

  void port_status_cb(bm::DevMgrIface::port_t port,
                      const bm::DevMgrIface::PortStatus port_status);

  std::shared_ptr<bm::BaseSwitch> switch_target;
  std::string grpc_server_addr;
  bm::DevMgrIface::port_t cpu_port;
  std::string dp_grpc_server_addr;
  int dp_grpc_server_port;
  DataplaneInterfaceServiceImpl *dp_service;
  std::unique_ptr<grpc::Server> dp_grpc_server;
#ifdef WITH_SYSREPO
  std::unique_ptr<SysrepoDriver> sysrepo_driver;
#endif // WITH_SYSREPO
  std::shared_ptr<SSLOptions> ssl_options;
  size_t nb_queues_per_port;
};

} // namespace switch_runner

#endif // SERVICES_SWITCH_RUNNER_H_
