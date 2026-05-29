// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/pipeline.h>
#include <bm/bm_sim/event_logger.h>
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/debugger.h>
#include <bm/bm_sim/packet.h>

namespace bm {

void
Pipeline::apply(Packet *pkt) {
  BMELOG(pipeline_start, *pkt, *this);
  // TODO(antonin)
  // this is temporary while we experiment with the debugger
  DEBUGGER_NOTIFY_CTR(
      Debugger::PacketId::make(pkt->get_packet_id(), pkt->get_copy_id()),
      DBG_CTR_CONTROL | get_id());
  BMLOG_DEBUG_PKT(*pkt, "Pipeline '{}': start", get_name());
  const ControlFlowNode *node = first_node;
  while (node) {
    if (pkt->is_marked_for_exit()) {
      BMLOG_DEBUG_PKT(*pkt, "Packet is marked for exit, interrupting pipeline");
      break;
    }
    node = (*node)(pkt);
  }
  BMELOG(pipeline_done, *pkt, *this);
  DEBUGGER_NOTIFY_CTR(
      Debugger::PacketId::make(pkt->get_packet_id(), pkt->get_copy_id()),
      DBG_CTR_EXIT(DBG_CTR_CONTROL) | get_id());
  BMLOG_DEBUG_PKT(*pkt, "Pipeline '{}': end", get_name());
}

}  // namespace bm
