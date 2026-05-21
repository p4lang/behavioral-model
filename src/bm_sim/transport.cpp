// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/transport.h>

#include <iostream>
#include <memory>
#include <string>

namespace bm {

// TODO(antonin): remove this?
class TransportStdout : public TransportIface {
 public:
  TransportStdout() { }

 private:
  int open_() override {
    return 0;
  }

  int send_(const std::string &msg) const override {
    std::cout << msg << std::endl;
    return 0;
  }

  int send_(const char *msg, int len) const override {
    (void) len;  // compiler warning
    std::cout << msg << std::endl;
    return 0;
  }

  int send_msgs_(const std::initializer_list<std::string> &msgs)
      const override {
    for (const auto &msg : msgs) {
      send(msg);
    }
    return 0;
  }

  int send_msgs_(const std::initializer_list<MsgBuf> &msgs) const override {
    for (const auto &msg : msgs) {
      send(msg.buf, msg.len);
    }
    return 0;
  }
};

class TransportDummy : public TransportIface {
 public:
  TransportDummy() { }

 private:
  int open_() override {
    return 0;
  }

  int send_(const std::string &msg) const override {
    (void) msg;  // compiler warning
    return 0;
  }

  int send_(const char *msg, int len) const override {
    (void) msg;  // compiler warning
    (void) len;
    return 0;
  }

  int send_msgs_(
      const std::initializer_list<std::string> &msgs) const override {
    (void) msgs;  // compiler warning
    return 0;
  }

  int send_msgs_(
      const std::initializer_list<MsgBuf> &msgs) const override {
    (void) msgs;  // compiler warning
    return 0;
  }
};

std::unique_ptr<TransportIface>
TransportIface::make_dummy() {
  return std::unique_ptr<TransportDummy>(new TransportDummy());
}

std::unique_ptr<TransportIface>
TransportIface::make_stdout() {
  return std::unique_ptr<TransportStdout>(new TransportStdout());
}

}  // namespace bm
