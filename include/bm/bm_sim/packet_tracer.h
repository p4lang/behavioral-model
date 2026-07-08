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

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "packet_trace.pb.h"

namespace bm {

class Packet;

class TraceTreeWrapper {
 public:
  TraceTreeWrapper(uint64_t packet_id, uint32_t ingress_port);
  ~TraceTreeWrapper();

 private:
  friend class PacketTraceContext;

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

  std::shared_ptr<TraceTreeWrapper> get_wrapper() const {
    return tree_wrapper_;
  }

 private:
  std::shared_ptr<TraceTreeWrapper> tree_wrapper_;
  p4::bm::TraceTree* current_node_;
};

//! Protobuf trace backend.
class PacketTracer {
 public:
  static PacketTracer* get() {
    static PacketTracer instance;
    return &instance;
  }

  //! Set the output directory for trace files.
  void set_output_dir(const std::string& output_dir);

  //! Write a completed trace to the output directory as txtpb.
  void flush_trace(const p4::bm::PacketTrace& trace);

 private:
  PacketTracer() = default;

  bool enabled_{false};
  std::string output_dir_;
};

}  // namespace bm

#endif  // BM_BM_SIM_PACKET_TRACER_H_
