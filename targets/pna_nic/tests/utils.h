/* Copyright 2024 Marvell Technology, Inc.
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
 * Rupesh Chiluka (rchiluka@marvell.com)
 *
 */

#ifndef PNA_NIC_TESTS_UTILS_H_
#define PNA_NIC_TESTS_UTILS_H_

#include <bm/bm_sim/nn.h>

#include <nanomsg/pubsub.h>

#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <unordered_map>

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

#endif  // PNA_NIC_TESTS_UTILS_H_