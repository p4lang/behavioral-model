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

#ifndef BM_BM_APPS_PACKET_PIPE_H_
#define BM_BM_APPS_PACKET_PIPE_H_

#include <string>
#include <thread>
#include <mutex>
#include <memory>
#include <functional>

namespace bm_apps {

class PacketInjectImp;

class PacketInject {
 public:
  // the library owns the memory, make a copy if you need before returning
  using PacketReceiveCb = std::function<void(int port_num, const char *buffer,
                                             int len, void *cookie)>;

  explicit PacketInject(const std::string &addr);

  ~PacketInject();

  void start();

  void set_packet_receiver(const PacketReceiveCb &cb, void *cookie);

  void send(int port_num, const char *buffer, int len);

  // these 4 port_* functions are optional, depending on receiver configuration
  void port_add(int port_num);

  void port_remove(int port_num);

  void port_bring_up(int port_num);

  void port_bring_down(int port_num);

  // returns 0 if success, 1 otherwise
  // for now, this is for testing only, bmv2 will return "not supported" for
  // every request
  int request_info(int port_num, int info_type, std::string *v);

 private:
  // cannot use {nullptr} with pimpl
  std::unique_ptr<PacketInjectImp> pimp;
};

}  // namespace bm_apps

#endif  // BM_BM_APPS_PACKET_PIPE_H_
