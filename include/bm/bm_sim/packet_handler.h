/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BM_BM_SIM_PACKET_HANDLER_H_
#define BM_BM_SIM_PACKET_HANDLER_H_

#include <functional>

namespace bm {

class PacketDispatcherIface {
 public:
  using PacketHandler = std::function<void(int port_num, const char *buffer,
                                           int len, void* cookie)>;
  enum class ReturnCode {
    SUCCESS,
    UNSUPPORTED,
    ERROR
  };

  virtual ReturnCode set_packet_handler(const PacketHandler &handler,
                                        void* cookie) = 0;
};

class PacketReceiverIface {
 public:
  virtual void send_packet(int port_num, const char* buffer, int len) = 0;
};

}  // namespace bm

#endif  // BM_BM_SIM_PACKET_HANDLER_H_
