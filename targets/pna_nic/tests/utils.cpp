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

#include "utils.h"

PacketInReceiver::PacketInReceiver() { }

void
PacketInReceiver::receive(int port_num, const char *buffer, int len,
                          void *cookie) {
  (void) cookie;
  std::unique_lock<std::mutex> lock(mutex);
  while (status != Status::CAN_RECEIVE) {
    can_receive.wait(lock);
  }
  buffer_.insert(buffer_.end(), buffer, buffer + len);
  port = port_num;
  status = Status::CAN_READ;
  can_read.notify_one();
}

size_t
PacketInReceiver::read(char *dst, size_t max_size, int *recv_port) {
  std::unique_lock<std::mutex> lock(mutex);
  while (status != Status::CAN_READ) {
    can_read.wait(lock);
  }
  size_t size = std::min(max_size, buffer_.size());
  std::copy(buffer_.begin(), buffer_.begin() + size, dst);
  buffer_.clear();
  *recv_port = port;
  status = Status::CAN_RECEIVE;
  can_receive.notify_one();
  return size;
}

PacketInReceiver::Status
PacketInReceiver::check_status() {
  std::unique_lock<std::mutex> lock(mutex);
  return status;
}