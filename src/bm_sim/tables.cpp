// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/debugger.h>
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/tables.h>

#include <string>

namespace bm {

MatchActionTable::MatchActionTable(
    const std::string &name, p4object_id_t id,
    std::unique_ptr<MatchTableAbstract> match_table)
    : ControlFlowNode(name, id),
      match_table(std::move(match_table)) { }

const ControlFlowNode *
MatchActionTable::operator()(Packet *pkt) const {
  // TODO(antonin) this is temporary while we experiment with the debugger
  DEBUGGER_NOTIFY_CTR(
      Debugger::PacketId::make(pkt->get_packet_id(), pkt->get_copy_id()),
      DBG_CTR_TABLE | get_id());
  BMLOG_TRACE_PKT(*pkt, "Applying table '{}'", get_name());
  const auto next = match_table->apply_action(pkt);
  DEBUGGER_NOTIFY_CTR(
      Debugger::PacketId::make(pkt->get_packet_id(), pkt->get_copy_id()),
      DBG_CTR_EXIT(DBG_CTR_TABLE) | get_id());
  return next;
}

}  // namespace bm
