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

#include <bm/bm_sim/_assert.h>
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/options_parse.h>

#include <bm/PI/pi.h>

#include <PI/frontends/proto/device_mgr.h>
#include <PI/frontends/proto/logging.h>

#include <PI/proto/pi_server.h>

#include <PI/pi.h>
#include <PI/target/pi_imp.h>

#include <grpc++/grpc++.h>

#include <p4/bm/dataplane_interface.grpc.pb.h>

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "simple_switch.h"

#include "switch_runner.h"

#ifdef WITH_SYSREPO
#include "switch_sysrepo.h"
#endif  // WITH_SYSREPO

namespace sswitch_grpc {

namespace {

using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;

using ServerReaderWriter = grpc::ServerReaderWriter<
  p4::bm::PacketStreamResponse, p4::bm::PacketStreamRequest>;

class DataplaneInterfaceServiceImpl
    : public p4::bm::DataplaneInterface::Service,
      public bm::DevMgrIface {
 public:
  explicit DataplaneInterfaceServiceImpl(bm::device_id_t device_id)
      : device_id(device_id) {
    p_monitor = bm::PortMonitorIface::make_passive(device_id);
  }

 private:
  using Lock = std::lock_guard<std::mutex>;

  Status PacketStream(ServerContext *context,
                      ServerReaderWriter *stream) override {
    {
      Lock lock(mutex);
      if (!started)
        return Status(StatusCode::UNAVAILABLE, "not ready");
      if (active) {
        return Status(StatusCode::RESOURCE_EXHAUSTED,
                      "only one client authorized at a time");
      }
      active = true;
      this->context = context;
      this->stream = stream;
    }
    p4::bm::PacketStreamRequest request;
    while (this->stream->Read(&request)) {
      if (request.device_id() != device_id) {
        continue;
      }
      const auto &packet = request.packet();
      if (packet.empty()) continue;
      if (!pkt_handler) continue;
      pkt_handler(request.port(), packet.data(), packet.size(), pkt_cookie);
    }
    auto &runner = sswitch_grpc::SimpleSwitchGrpcRunner::get_instance();
    runner.block_until_all_packets_processed();
    Lock lock(mutex);
    active = false;
    return Status::OK;
  }

  ReturnCode port_add_(const std::string &iface_name, port_t port_num,
                       const PortExtras &port_extras) override {
    _BM_UNUSED(iface_name);
    _BM_UNUSED(port_num);
    _BM_UNUSED(port_extras);
    return ReturnCode::SUCCESS;
  }

  ReturnCode port_remove_(port_t port_num) override {
    _BM_UNUSED(port_num);
    return ReturnCode::SUCCESS;
  }

  void transmit_fn_(int port_num, const char *buffer, int len) override {
    p4::bm::PacketStreamResponse response;
    response.set_device_id(device_id);
    response.set_port(port_num);
    response.set_packet(buffer, len);
    Lock lock(mutex);
    if (active) stream->Write(response);
  }

  void start_() override {
    Lock lock(mutex);
    started = true;
  }

  ReturnCode set_packet_handler_(const PacketHandler &handler, void *cookie)
      override {
    pkt_handler = handler;
    pkt_cookie = cookie;
    return ReturnCode::SUCCESS;
  }

  bool port_is_up_(port_t port) const override {
    _BM_UNUSED(port);
    return true;
  }

  std::map<port_t, PortInfo> get_port_info_() const override {
    return {};
  }

  bm::device_id_t device_id;
  // protects the shared state (active) and prevents concurrent Write calls by
  // different threads
  std::mutex mutex{};
  bool started{false};
  bool active{false};
  ServerContext *context{nullptr};
  ServerReaderWriter *stream{nullptr};
  PacketHandler pkt_handler{};
  void *pkt_cookie{nullptr};
};

}  // namespace

SimpleSwitchGrpcRunner::SimpleSwitchGrpcRunner(int max_port, bool enable_swap,
                                               std::string grpc_server_addr,
                                               int cpu_port,
                                               std::string dp_grpc_server_addr)
    : simple_switch(new SimpleSwitch(max_port, enable_swap)),
      grpc_server_addr(grpc_server_addr), cpu_port(cpu_port),
      dp_grpc_server_addr(dp_grpc_server_addr),
      dp_grpc_server(nullptr) {
#ifdef WITH_SYSREPO
      sysrepo_driver = std::unique_ptr<SysrepoDriver>(new SysrepoDriver(
          simple_switch->get_device_id(), simple_switch.get()));
#endif  // WITH_SYSREPO
}

int
SimpleSwitchGrpcRunner::init_and_start(const bm::OptionsParser &parser) {
  std::unique_ptr<bm::DevMgrIface> my_dev_mgr = nullptr;
  if (!dp_grpc_server_addr.empty()) {
    auto service = new DataplaneInterfaceServiceImpl(parser.device_id);
    grpc::ServerBuilder builder;
    builder.SetSyncServerOption(
      grpc::ServerBuilder::SyncServerOption::NUM_CQS, 1);
    builder.SetSyncServerOption(
      grpc::ServerBuilder::SyncServerOption::MIN_POLLERS, 1);
    builder.SetSyncServerOption(
      grpc::ServerBuilder::SyncServerOption::MAX_POLLERS, 1);
    builder.AddListeningPort(dp_grpc_server_addr,
                             grpc::InsecureServerCredentials(),
                             &dp_grpc_server_port);
    builder.RegisterService(service);
    dp_grpc_server = builder.BuildAndStart();
    my_dev_mgr.reset(service);
  }

  // Even when using gNMI to manage ports, it is convenient to be able to use
  // the --interface / -i command-line option. However we have to "intercept"
  // the options before the call to DevMgr::port_add, otherwise we would try to
  // add the ports twice (once when calling Switch::init_from_options_parser and
  // once when we are notified by sysrepo of the YANG datastore change).
  // We therefore save the interface list provided on the command-line and we
  // call SysrepoDriver::add_iface at the end of this method after we start the
  // sysrepo subscriber.
  const bm::OptionsParser *parser_ptr;
#ifdef WITH_SYSREPO
  auto new_parser = parser;
  auto &interfaces = new_parser.ifaces;
  auto saved_interfaces = interfaces;
  interfaces.clear();
  parser_ptr = &new_parser;
#else
  parser_ptr = &parser;
#endif  // WITH_SYSREPO

  int status = simple_switch->init_from_options_parser(
      *parser_ptr, nullptr, std::move(my_dev_mgr));
  if (status != 0) return status;

  // PortMonitor saves the CB by reference so we cannot use this code; it seems
  // that at this stage we do not need the CB any way.
  // using PortStatus = bm::DevMgrIface::PortStatus;
  // auto port_cb = std::bind(&SimpleSwitchGrpcRunner::port_status_cb, this,
  //                          std::placeholders::_1, std::placeholders::_2);
  // simple_switch->register_status_cb(PortStatus::PORT_ADDED, port_cb);
  // simple_switch->register_status_cb(PortStatus::PORT_REMOVED, port_cb);

  // check if CPU port number is also used by --interface
  // TODO(antonin): ports added dynamically?
  if (cpu_port >= 0) {
    if (parser.ifaces.find(cpu_port) != parser.ifaces.end()) {
      bm::Logger::get()->error("Cpu port {} is used as a data port", cpu_port);
      return 1;
    }
  }

  if (cpu_port >= 0) {
    auto transmit_fn = [this](int port_num, const char *buf, int len) {
      if (port_num == cpu_port) {
        BMLOG_DEBUG("Transmitting packet-in");
        auto status = pi_packetin_receive(
            simple_switch->get_device_id(), buf, static_cast<size_t>(len));
        if (status != PI_STATUS_SUCCESS)
          bm::Logger::get()->error("Error when transmitting packet-in");
      } else {
        simple_switch->transmit_fn(port_num, buf, len);
      }
    };
    simple_switch->set_transmit_fn(transmit_fn);
  }

  bm::pi::register_switch(simple_switch.get(), cpu_port);

  {
    using pi::fe::proto::LogWriterIface;
    using pi::fe::proto::LoggerConfig;
    class P4RuntimeLogger : public LogWriterIface {
      void write(Severity severity, const char *msg) override {
        auto severity_map = [&severity]() {
          namespace spdL = spdlog::level;
          switch (severity) {
            case Severity::TRACE : return spdL::trace;
            case Severity::DEBUG: return spdL::debug;
            case Severity::INFO: return spdL::info;
            case Severity::WARN: return spdL::warn;
            case Severity::ERROR: return spdL::err;
            case Severity::CRITICAL: return spdL::critical;
          }
          return spdL::off;
        };
        // TODO(antonin): use a separate logger with a separate name
        bm::Logger::get()->log(severity_map(), "[P4Runtime] {}", msg);
      }
    };
    LoggerConfig::set_writer(std::make_shared<P4RuntimeLogger>());
  }
  using pi::fe::proto::DeviceMgr;
  DeviceMgr::init(256);
  PIGrpcServerRunAddr(grpc_server_addr.c_str());

#ifdef WITH_SYSREPO
  if (!sysrepo_driver->start()) return 1;
  for (const auto &p : saved_interfaces)
    sysrepo_driver->add_iface(p.first, p.second);
#endif  // WITH_SYSREPO

  simple_switch->start_and_return();

  return 0;
}

void
SimpleSwitchGrpcRunner::wait() {
  PIGrpcServerWait();
}

void
SimpleSwitchGrpcRunner::shutdown() {
  if (!dp_grpc_server_addr.empty()) dp_grpc_server->Shutdown();
  PIGrpcServerShutdown();
}

void
SimpleSwitchGrpcRunner::mirroring_mapping_add(int mirror_id, int egress_port) {
  simple_switch->mirroring_mapping_add(mirror_id, egress_port);
}

void
SimpleSwitchGrpcRunner::block_until_all_packets_processed() {
  simple_switch->block_until_no_more_packets();
}

SimpleSwitchGrpcRunner::~SimpleSwitchGrpcRunner() {
  PIGrpcServerCleanup();
}

void
SimpleSwitchGrpcRunner::port_status_cb(
    bm::DevMgrIface::port_t port, const bm::DevMgrIface::PortStatus status) {
  _BM_UNUSED(port);
  _BM_UNUSED(status);
}

}  // namespace sswitch_grpc
