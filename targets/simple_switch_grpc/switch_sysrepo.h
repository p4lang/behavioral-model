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

#ifndef SIMPLE_SWITCH_GRPC_SWITCH_SYSREPO_H_
#define SIMPLE_SWITCH_GRPC_SWITCH_SYSREPO_H_

#include <bm/bm_sim/device_id.h>

#include <memory>
#include <string>

namespace bm {

class DevMgr;

}  // namespace bm

namespace sswitch_grpc {

class PortStateMap;
class SysrepoSubscriber;
class SysrepoStateProvider;

class SysrepoDriver {
 public:
  SysrepoDriver(bm::device_id_t device_id, bm::DevMgr *dev_mgr);
  ~SysrepoDriver();

  bool start();

  // Used to add interfaces provided on the command-line with --interface / -i
  void add_iface(int port, const std::string &name);

 private:
  const bm::device_id_t my_device_id;
  const bm::DevMgr *dev_mgr;  // non-owning pointer
  std::unique_ptr<PortStateMap> port_state_map;
  std::unique_ptr<SysrepoSubscriber> sysrepo_subscriber;
  std::unique_ptr<SysrepoStateProvider> sysrepo_state_provider;
};

}  // namespace sswitch_grpc

#endif  // SIMPLE_SWITCH_GRPC_SWITCH_SYSREPO_H_
