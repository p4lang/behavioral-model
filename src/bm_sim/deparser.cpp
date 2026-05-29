// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/deparser.h>
#include <bm/bm_sim/debugger.h>
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/event_logger.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/checksums.h>
#include <bm/bm_sim/phv.h>
#include <bm/bm_sim/actions.h>

#include <string>

namespace bm {

struct DeparserOp {
  virtual ~DeparserOp() {}
  virtual void operator()(Packet *pkt) const = 0;
};

struct DeparserOpMethodCall : DeparserOp {
  ActionFnEntry action;

  explicit DeparserOpMethodCall(ActionFn *action_fn)
      : action(action_fn) { }

  void operator()(Packet *pkt) const override {
    action.execute(pkt);
  }
};

Deparser::Deparser(const std::string &name, p4object_id_t id)
    : NamedP4Object(name, id) {}
Deparser::~Deparser() {}

size_t
Deparser::get_headers_size(const PHV &phv) const {
  size_t headers_size = 0;
  for (auto it = headers.begin(); it != headers.end(); ++it) {
    const Header &header = phv.get_header(*it);
    if (header.is_valid()) {
      headers_size += header.get_nbytes_packet();
    }
  }
  return headers_size;
}

void
Deparser::deparse(Packet *pkt) const {
  const PHV *phv = pkt->get_phv();
  BMELOG(deparser_start, *pkt, *this);
  // TODO(antonin)
  // this is temporary while we experiment with the debugger
  DEBUGGER_NOTIFY_CTR(
      Debugger::PacketId::make(pkt->get_packet_id(), pkt->get_copy_id()),
      DBG_CTR_DEPARSER | get_id());
  BMLOG_DEBUG_PKT(*pkt, "Deparser '{}': start", get_name());
  update_checksums(pkt);
  char *data = pkt->prepend(get_headers_size(*phv));
  int bytes_parsed = 0;
  {
    RegisterSync::RegisterLocks RL;
    register_sync.lock(&RL);

    for (auto &deparser_op : deparser_ops)
      (*deparser_op)(pkt);
  }
  // invalidating headers, and resetting header stacks is done in the Packet
  // destructor, when the PHV is released
  for (auto it = headers.begin(); it != headers.end(); ++it) {
    const auto &header = phv->get_header(*it);
    if (header.is_valid()) {
      BMELOG(deparser_emit, *pkt, *it);
      BMLOG_DEBUG_PKT(*pkt, "Deparsing header '{}'", header.get_name());
      header.deparse(data + bytes_parsed);
      bytes_parsed += header.get_nbytes_packet();
    }
  }
  BMELOG(deparser_done, *pkt, *this);
  DEBUGGER_NOTIFY_CTR(
      Debugger::PacketId::make(pkt->get_packet_id(), pkt->get_copy_id()),
      DBG_CTR_EXIT(DBG_CTR_DEPARSER) | get_id());
  BMLOG_DEBUG_PKT(*pkt, "Deparser '{}': end", get_name());
}

void
Deparser::update_checksums(Packet *pkt) const {
  for (const Checksum *checksum : checksums) {
    checksum->update(pkt);
    BMELOG(checksum_update, *pkt, *checksum);
  }
}

void
Deparser::add_method_call(ActionFn *action_fn) {
  action_fn->grab_register_accesses(&register_sync);
  deparser_ops.emplace_back(new DeparserOpMethodCall(action_fn));
}

}  // namespace bm
