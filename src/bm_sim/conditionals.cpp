// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/conditionals.h>
#include <bm/bm_sim/event_logger.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/logger.h>

#include <cassert>

namespace bm {

const ControlFlowNode *
Conditional::operator()(Packet *pkt) const {
  // TODO(antonin)
  // this is temporary while we experiment with the debugger
  DEBUGGER_NOTIFY_CTR(
      Debugger::PacketId::make(pkt->get_packet_id(), pkt->get_copy_id()),
      DBG_CTR_CONDITION | get_id());
  PHV *phv = pkt->get_phv();
  bool result = eval(*phv);
  BMELOG(condition_eval, *pkt, *this, result);

  // It would be nicer to see the following additional info in the log:
  //
  // + The full expression even if it spans multiple lines.
  // + The current values of all variables involved in evaluating the
  //   expression.
  BMLOG_TRACE_SI_PKT(*pkt, get_source_info(), "Condition \"{}\" ({}) is {}",
                     (get_source_info() == nullptr) ? get_name() :
                     get_source_info()->get_source_fragment(),
                     get_name(), result);
  DEBUGGER_NOTIFY_UPDATE_V(
      Debugger::PacketId::make(pkt->get_packet_id(), pkt->get_copy_id()),
      Debugger::FIELD_COND, result);
  DEBUGGER_NOTIFY_CTR(
      Debugger::PacketId::make(pkt->get_packet_id(), pkt->get_copy_id()),
      DBG_CTR_EXIT(DBG_CTR_CONDITION) | get_id());
  return result ? true_next : false_next;
}

}  // namespace bm
