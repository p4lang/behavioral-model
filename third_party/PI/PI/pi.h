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

//! @file

#ifndef PI_INC_PI_PI_H_
#define PI_INC_PI_PI_H_

#include "pi_act_prof.h"
#include "pi_base.h"
#include "pi_counter.h"
#include "pi_meter.h"
#include "pi_tables.h"

#ifdef __cplusplus
extern "C" {
#endif

//! Returns the P4 config (p4info) associated with that device id, NULL if the
//! device is not assigned.
const pi_p4info_t *pi_get_device_p4info(pi_dev_id_t dev_id);

//! Addresses for RPC server and notifications server (PUBSUB)
typedef struct {
  char *rpc_addr;
  char *notifications_addr;
} pi_remote_addr_t;

// TODO(antonin): remove max_devices as it is not needed any more
//! Init function for PI
pi_status_t pi_init(size_t max_devices, pi_remote_addr_t *remote_addr);

typedef struct {
  int end_of_extras;
  const char *key;
  const char *v;
} pi_assign_extra_t;

//! Assigns a P4 config to a device. Different targets may need different
//! information at that stage, so arbitary parameters can be provided using \p
//! extra. \p p4info is NULL except if the device is already configured.
pi_status_t pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                             pi_assign_extra_t *extra);

//! Inititate a P4 config update on a device. After this function is called,
//! packets will still be processed by the target using the old config, but all
//! PI calls (e.g. table updates) will apply to the new config. When you are
//! ready to swap configs at the target, call pi_update_device_end. Different
//! target may need a different input at that stage, which is what \p
//! device_data is for.
pi_status_t pi_update_device_start(pi_dev_id_t dev_id,
                                   const pi_p4info_t *p4info,
                                   const char *device_data,
                                   size_t device_data_size);

//! Terminates a P4 config update sequence, see pi_update_device_start.
pi_status_t pi_update_device_end(pi_dev_id_t dev_id);

//! Check if a device was assigned.
bool pi_is_device_assigned(pi_dev_id_t dev_id);

size_t pi_num_devices();

size_t pi_get_device_ids(pi_dev_id_t *dev_ids, size_t max_num_devices);

//! Remove a device.
pi_status_t pi_remove_device(pi_dev_id_t dev_id);

//! Init a client session.
pi_status_t pi_session_init(pi_session_handle_t *session_handle);

//! Terminate a client session.
pi_status_t pi_session_cleanup(pi_session_handle_t session_handle);

//! Start a batch of operations for the session. For a given session, there can
//! only be one ongoing batch operation.
pi_status_t pi_batch_begin(pi_session_handle_t session_handle);

//! End the ongoing batch for the session. If \p hw_sync is true, the call will
//! block until all the operations have been committed to hardware.
pi_status_t pi_batch_end(pi_session_handle_t session_handle, bool hw_sync);

//! PI cleanup function.
pi_status_t pi_destroy();

//! Callback type for packet-in.
typedef void (*PIPacketInCb)(pi_dev_id_t dev_id, const char *pkt, size_t size,
                             void *cb_cookie);
//! Register a callback for packet-in events, for a given device.
pi_status_t pi_packetin_register_cb(pi_dev_id_t dev_id, PIPacketInCb cb,
                                    void *cb_cookie);
//! Register a default callback for packet-in, which will be used if no specific
//! callback was specified for the device which issued the packet-in event.
pi_status_t pi_packetin_register_default_cb(PIPacketInCb cb, void *cb_cookie);
//! De-register a packet-in callback for a given device
pi_status_t pi_packetin_deregister_cb(pi_dev_id_t dev_id);
//! De-register default callback.
pi_status_t pi_packetin_deregister_default_cb();

//! Inject a packet in the specified device.
pi_status_t pi_packetout_send(pi_dev_id_t dev_id, const char *pkt, size_t size);

//! Callback type for port status events.
typedef void (*PIPortStatusCb)(pi_dev_id_t dev_id, pi_port_t port,
                               pi_port_status_t status, void *cb_cookie);
//! Register a callback for port status events, for a given device.
pi_status_t pi_port_status_register_cb(pi_dev_id_t dev_id, PIPortStatusCb cb,
                                       void *cb_cookie);
//! Register a default callback for port status events, which will be used if no
//! specific callback was specified for the device which issued the event.
pi_status_t pi_port_status_register_default_cb(PIPortStatusCb cb,
                                               void *cb_cookie);
//! De-register a port status event callback for a given device
pi_status_t pi_port_status_deregister_cb(pi_dev_id_t dev_id);
//! De-register default callback.
pi_status_t pi_port_status_deregister_default_cb();

pi_status_t pi_port_status_get(pi_dev_id_t dev_id, pi_port_t port,
                               pi_port_status_t *status);

// TODO(antonin): move this to pi_tables?
// When adding a table entry, the configuration for direct resources associated
// with the entry can be provided. The config is then passed as a generic void *
// pointer. For the sake of the messaging system, we need a way to serialize /
// de-serialize the config, thus the need for these:
// size when serialized
typedef size_t (*PIDirectResMsgSizeFn)(const void *config);
// emit function for serialization
typedef size_t (*PIDirectResEmitFn)(char *dst, const void *config);
// retrieve function for de-serialization
typedef size_t (*PIDirectResRetrieveFn)(const char *src, void *config);
// size_of is the size of memory blob required by retrieve function, alignment
// is guaranteed to be maximum for the architecture (e.g. 16 bytes for x86_64)
pi_status_t pi_direct_res_register(pi_res_type_id_t res_type,
                                   PIDirectResMsgSizeFn msg_size_fn,
                                   PIDirectResEmitFn emit_fn, size_t size_of,
                                   PIDirectResRetrieveFn retrieve_fn);

// set ptr to NULL if not interested
pi_status_t pi_direct_res_get_fns(pi_res_type_id_t res_type,
                                  PIDirectResMsgSizeFn *msg_size_fn,
                                  PIDirectResEmitFn *emit_fn, size_t *size_of,
                                  PIDirectResRetrieveFn *retrieve_fn);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_H_
