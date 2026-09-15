/*
 * SPDX-FileCopyrightText: 2026 Yuao Ma
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! @file packet_tracer.h
//!
//! Protobuf-based structured packet tracing backend.

#ifndef BM_BM_SIM_PACKET_TRACER_H_
#define BM_BM_SIM_PACKET_TRACER_H_

#include <bm/config.h>

#ifdef BM_PACKET_TRACE_ON

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "event_observer.h"
#include "packet_trace.pb.h"

namespace bm {

class Packet;

class TraceTreeWrapper {
 public:
  TraceTreeWrapper(uint64_t packet_id, uint32_t ingress_port);
  ~TraceTreeWrapper();

 private:
  friend class PacketTraceContext;

  std::mutex mutex_;
  p4::bm::PacketTrace root_trace_;
};

//! Per-packet trace accumulator. One instance is attached to each Packet object
//! when tracing is enabled. Accumulates TraceEvent messages in chronological
//! order.
class PacketTraceContext {
 public:
  PacketTraceContext(uint64_t packet_id, uint32_t ingress_port);
  PacketTraceContext(std::shared_ptr<TraceTreeWrapper> tree_wrapper,
                     p4::bm::TraceTree* node);

  //! Add a trace event. The event is moved into the internal trace.
  void add_event(p4::bm::TraceEvent event);

  std::shared_ptr<TraceTreeWrapper> get_wrapper() const {
    return tree_wrapper_;
  }

 private:
  std::shared_ptr<TraceTreeWrapper> tree_wrapper_;
  p4::bm::TraceTree* current_node_;
};

//! Protobuf trace backend.
class PacketTracer : public EventObserverIface {
 public:
  static PacketTracer* get() {
    static PacketTracer instance;
    return &instance;
  }

  //! Set the output directory for trace files. Must be called once during
  //! initialization, before any packets are processed.
  void set_output_dir(const std::string& output_dir);

  //! Write a completed trace to the output directory as txtpb.
  //! Thread-safe: each call writes to a unique file keyed by packet_id.
  void flush_trace(const p4::bm::PacketTrace& trace);

  //! Attach a fresh trace context to a packet entering the switch.
  void attach_trace_ctx(Packet* packet);

  void packet_in(const Packet& packet) override;
  void packet_out(const Packet& packet) override;

  void parser_start(const Packet& packet, const Parser& parser) override;
  void parser_done(const Packet& packet, const Parser& parser) override;
  void parser_extract(const Packet& packet, header_id_t header) override;

  void deparser_start(const Packet& packet, const Deparser& deparser) override;
  void deparser_done(const Packet& packet, const Deparser& deparser) override;
  void deparser_emit(const Packet& packet, header_id_t header) override;

  void checksum_update(const Packet& packet, const Checksum& checksum) override;

  void pipeline_start(const Packet& packet, const Pipeline& pipeline) override;
  void pipeline_done(const Packet& packet, const Pipeline& pipeline) override;

  void condition_eval(const Packet& packet, const Conditional& cond,
                      bool result) override;
  void table_hit(const Packet& packet, const MatchTableAbstract& table,
                 entry_handle_t handle) override;
  void table_miss(const Packet& packet,
                  const MatchTableAbstract& table) override;

  void action_execute(const Packet& packet, const ActionFn& action_fn,
                      const ActionData& action_data) override;

  void config_change() override;

 private:
  PacketTracer() = default;

  bool enabled_{false};
  std::string output_dir_;
};

}  // namespace bm

#endif  // BM_PACKET_TRACE_ON

#endif  // BM_BM_SIM_PACKET_TRACER_H_
