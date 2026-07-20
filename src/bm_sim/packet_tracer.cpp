// SPDX-FileCopyrightText: 2026 Yuao Ma
//
// SPDX-License-Identifier: Apache-2.0

#include <bm/bm_sim/packet_tracer.h>

#ifdef BM_PACKET_TRACE_ON

#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/packet.h>
#include <google/protobuf/text_format.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <utility>

namespace bm {

// ---------- TraceTreeWrapper ----------

TraceTreeWrapper::TraceTreeWrapper(uint64_t packet_id, uint32_t ingress_port) {
  auto* input = root_trace_.mutable_input();
  input->set_packet_id(packet_id);
  input->set_ingress_port(ingress_port);
}

TraceTreeWrapper::~TraceTreeWrapper() {
  PacketTracer::get()->flush_trace(root_trace_);
}

// ---------- PacketTraceContext ----------

PacketTraceContext::PacketTraceContext(uint64_t packet_id,
                                       uint32_t ingress_port) {
  tree_wrapper_ = std::make_shared<TraceTreeWrapper>(packet_id, ingress_port);
  current_node_ = tree_wrapper_->root_trace_.mutable_root();
}

PacketTraceContext::PacketTraceContext(
    std::shared_ptr<TraceTreeWrapper> tree_wrapper, p4::bm::TraceTree* node)
    : tree_wrapper_(std::move(tree_wrapper)), current_node_(node) {}

// ---------- PacketTracer ----------

void PacketTracer::set_output_dir(const std::string& output_dir) {
  std::error_code ec;
  std::filesystem::create_directories(output_dir, ec);
  if (ec) {
    BMLOG_ERROR("Failed to create trace output directory '{}': {}", output_dir,
                ec.message());
    return;
  }

  output_dir_ = output_dir;
  enabled_ = true;
  BMLOG_DEBUG("Packet tracer initialized with output directory: {}",
              output_dir);
}

void PacketTracer::flush_trace(const p4::bm::PacketTrace& trace) {
  if (!enabled_) return;

  std::string txtpb;
  google::protobuf::TextFormat::PrintToString(trace, &txtpb);

  auto path = std::filesystem::path(output_dir_) /
              ("trace_" + std::to_string(trace.input().packet_id()) + ".txtpb");

  std::ofstream out(path);
  if (out.is_open()) {
    out << txtpb;
  } else {
    BMLOG_ERROR("Failed to write trace to {}", path.string());
  }
}

}  // namespace bm

#endif  // BM_PACKET_TRACE_ON
