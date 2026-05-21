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

#ifndef TEST_UTILS_UTILS_H_
#define TEST_UTILS_UTILS_H_

#include <bm/bm_sim/nn.h>

#include <nanomsg/pubsub.h>

#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <unordered_map>

class NNEventListener {
 public:
  enum NNEventType {
    TABLE_HIT = 12,
    TABLE_MISS = 13,
    ACTION_EXECUTE = 14
  };

  struct NNEvent {
    NNEventType type;
    int id;
  };

  explicit NNEventListener(const std::string &addr);

  ~NNEventListener();

  void start();

  void get_and_remove_events(const std::string &pid,
                             std::vector<NNEvent> *pevents,
                             size_t num_events,
                             unsigned int timeout_ms = 1000);

 private:
  void receive_loop();

  std::string addr{};
  nn::socket s;
  std::unordered_map<std::string, std::vector<NNEvent> > events;

  std::thread receive_thread{};
  bool stop_receive_thread{false};
  bool started{false};
  mutable std::mutex mutex{};
  mutable std::condition_variable cond_new_event{};
};


class PacketInReceiver {
 public:
  enum class Status { CAN_READ, CAN_RECEIVE };

  PacketInReceiver();

  void receive(int port_num, const char *buffer, int len, void *cookie);

  size_t read(char *dst, size_t max_size, int *recv_port);

  Status check_status();

 private:
  std::vector<char> buffer_{};
  int port;
  Status status{Status::CAN_RECEIVE};
  mutable std::mutex mutex{};
  mutable std::condition_variable can_receive{};
  mutable std::condition_variable can_read{};
};

#endif  // TEST_UTILS_UTILS_H_
