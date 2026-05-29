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

#ifndef BM_BM_SIM_TRANSPORT_H_
#define BM_BM_SIM_TRANSPORT_H_

#include <bm/config.h>

#include <string>
#include <initializer_list>
#include <memory>

namespace bm {

class TransportIface {
 public:
  struct MsgBuf {
    char *buf;
    unsigned int len;
  };

 public:
  virtual ~TransportIface() { }

  int open() {
    if (opened) return 1;
    opened = true;
    return open_();
  }

  int send(const std::string &msg) const {
    return send_(msg);
  }

  int send(const char *msg, int len) const {
    return send_(msg, len);
  }

  int send_msgs(const std::initializer_list<std::string> &msgs) const {
    return send_msgs_(msgs);
  }

  int send_msgs(const std::initializer_list<MsgBuf> &msgs) const {
    return send_msgs_(msgs);
  }

#ifdef BM_NANOMSG_ON
  static std::unique_ptr<TransportIface> make_nanomsg(const std::string &addr);
#endif
  static std::unique_ptr<TransportIface> make_dummy();
  static std::unique_ptr<TransportIface> make_stdout();

 private:
  virtual int open_() = 0;

  virtual int send_(const std::string &msg) const = 0;
  virtual int send_(const char *msg, int len) const = 0;

  virtual int send_msgs_(
      const std::initializer_list<std::string> &msgs) const = 0;
  virtual int send_msgs_(const std::initializer_list<MsgBuf> &msgs) const = 0;

  bool opened{false};
};

}  // namespace bm

#endif  // BM_BM_SIM_TRANSPORT_H_
