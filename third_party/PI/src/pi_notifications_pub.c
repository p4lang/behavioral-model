/* Copyright 2013-present Barefoot Networks, Inc.
 * SPDX-License-Identifier: Apache-2.0
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

#include <PI/int/rpc_common.h>
#include <PI/int/serialize.h>

#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>

#include <string.h>

#include "_assert.h"
#include "pi_notifications_pub.h"

static char *addr = NULL;
static int pub_socket = 0;

static size_t emit_notifications_topic(char *dst, const char *topic) {
  memcpy(dst, topic, sizeof(s_pi_notifications_topic_t));
  return sizeof(s_pi_notifications_topic_t);
}

static size_t learn_msg_size(const pi_learn_msg_t *msg) {
  size_t s = 0;
  s += sizeof(s_pi_learn_msg_hdr_t);
  s += msg->num_entries * msg->entry_size;
  return s;
}

static size_t emit_learn_msg(char *dst, const pi_learn_msg_t *msg) {
  size_t s = 0;
  s += emit_notifications_topic(dst + s, "PILEA|");
  s += emit_dev_tgt(dst + s, msg->dev_tgt);
  s += emit_p4_id(dst + s, msg->learn_id);
  s += emit_learn_msg_id(dst + s, msg->msg_id);
  s += emit_uint32(dst + s, msg->num_entries);
  s += emit_uint32(dst + s, msg->entry_size);
  memcpy(dst + s, msg->entries, msg->num_entries * msg->entry_size);
  return s;
}

static void pub_notification(char *msg, size_t msg_size) {
  int bytes_sent = nn_send(pub_socket, &msg, NN_MSG, 0);
  _PI_UNUSED(msg_size);
  _PI_UNUSED(bytes_sent);
  assert((size_t)bytes_sent == msg_size);
}

void pi_notifications_pub_learn(const pi_learn_msg_t *msg) {
  size_t pub_msg_size = learn_msg_size(msg);
  char *pub_msg = nn_allocmsg(pub_msg_size, 0);
  emit_learn_msg(pub_msg, msg);
  pub_notification(pub_msg, pub_msg_size);
}

void pi_notifications_pub_packetin(pi_dev_id_t dev_id, const char *pkt,
                                   size_t size) {
  size_t pub_msg_size = sizeof(s_pi_notifications_topic_t);
  pub_msg_size += sizeof(s_pi_dev_id_t);
  pub_msg_size += sizeof(uint32_t);
  pub_msg_size += size;
  char *pub_msg = nn_allocmsg(pub_msg_size, 0);

  char *msg = pub_msg;
  msg += emit_notifications_topic(msg, "PIPKT|");
  msg += emit_dev_id(msg, dev_id);
  msg += emit_uint32(msg, size);
  memcpy(msg, pkt, size);
  pub_notification(pub_msg, pub_msg_size);
}

pi_status_t pi_notifications_init(const char *notifications_addr) {
  assert(notifications_addr);
  addr = strdup(notifications_addr);
  pub_socket = nn_socket(AF_SP, NN_PUB);
  assert(pub_socket >= 0);
  if (nn_bind(pub_socket, addr) < 0) return PI_STATUS_NOTIF_BIND_ERROR;
  return PI_STATUS_SUCCESS;
}
