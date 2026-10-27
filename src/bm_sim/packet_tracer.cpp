// SPDX-FileCopyrightText: 2026 Yuao Ma
//
// SPDX-License-Identifier: Apache-2.0

#include <bm/bm_sim/packet_tracer.h>

#ifdef BM_PACKET_TRACE_ON

#include <bm/bm_sim/_assert.h>
#include <bm/bm_sim/deparser.h>
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/pipeline.h>
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

void PacketTraceContext::add_event(p4::bm::TraceEvent event) {
  std::lock_guard<std::mutex> lock(tree_wrapper_->mutex_);
  *current_node_->add_events() = std::move(event);
}

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

void PacketTracer::attach_trace_ctx(Packet* packet) {
  if (!enabled_) return;
  auto ctx = std::make_unique<PacketTraceContext>(packet->get_packet_id(),
                                                  packet->get_ingress_port());
  packet->set_trace_ctx(std::move(ctx));
}

namespace {

// Add a TraceEvent to the packet's trace context (if present).
void trace_add_event(const Packet& packet, p4::bm::TraceEvent event) {
  PacketTraceContext* ctx = packet.get_trace_ctx();
  if (ctx) {
    ctx->add_event(std::move(event));
  }
}

}  // namespace

void PacketTracer::packet_in(const Packet& packet) { _BM_UNUSED(packet); }

void PacketTracer::packet_out(const Packet& packet) { _BM_UNUSED(packet); }

void PacketTracer::parser_start(const Packet& packet, const Parser& parser) {
  p4::bm::TraceEvent ev;
  p4::bm::PipelineStageEvent* ps = ev.mutable_pipeline_stage();
  ps->set_stage_name(parser.get_name());
  ps->set_stage_kind(p4::bm::PipelineStageEvent::PARSER);
  ps->set_direction(p4::bm::PipelineStageEvent::ENTER);
  trace_add_event(packet, std::move(ev));
}

void PacketTracer::parser_done(const Packet& packet, const Parser& parser) {
  p4::bm::TraceEvent ev;
  p4::bm::PipelineStageEvent* ps = ev.mutable_pipeline_stage();
  ps->set_stage_name(parser.get_name());
  ps->set_stage_kind(p4::bm::PipelineStageEvent::PARSER);
  ps->set_direction(p4::bm::PipelineStageEvent::EXIT);
  trace_add_event(packet, std::move(ev));
}

void PacketTracer::parser_extract(const Packet& packet, header_id_t header) {
  _BM_UNUSED(packet);
  _BM_UNUSED(header);
}

void PacketTracer::deparser_start(const Packet& packet,
                                  const Deparser& deparser) {
  p4::bm::TraceEvent ev;
  p4::bm::PipelineStageEvent* ps = ev.mutable_pipeline_stage();
  ps->set_stage_name(deparser.get_name());
  ps->set_stage_kind(p4::bm::PipelineStageEvent::DEPARSER);
  ps->set_direction(p4::bm::PipelineStageEvent::ENTER);
  trace_add_event(packet, std::move(ev));
}

void PacketTracer::deparser_done(const Packet& packet,
                                 const Deparser& deparser) {
  p4::bm::TraceEvent ev;
  p4::bm::PipelineStageEvent* ps = ev.mutable_pipeline_stage();
  ps->set_stage_name(deparser.get_name());
  ps->set_stage_kind(p4::bm::PipelineStageEvent::DEPARSER);
  ps->set_direction(p4::bm::PipelineStageEvent::EXIT);
  trace_add_event(packet, std::move(ev));
}

void PacketTracer::deparser_emit(const Packet& packet, header_id_t header) {
  _BM_UNUSED(packet);
  _BM_UNUSED(header);
}

void PacketTracer::checksum_update(const Packet& packet,
                                   const Checksum& checksum) {
  _BM_UNUSED(packet);
  _BM_UNUSED(checksum);
}

void PacketTracer::pipeline_start(const Packet& packet,
                                  const Pipeline& pipeline) {
  p4::bm::TraceEvent ev;
  p4::bm::PipelineStageEvent* ps = ev.mutable_pipeline_stage();
  ps->set_stage_name(pipeline.get_name());
  ps->set_stage_kind(p4::bm::PipelineStageEvent::CONTROL);
  ps->set_direction(p4::bm::PipelineStageEvent::ENTER);
  trace_add_event(packet, std::move(ev));
}

void PacketTracer::pipeline_done(const Packet& packet,
                                 const Pipeline& pipeline) {
  p4::bm::TraceEvent ev;
  p4::bm::PipelineStageEvent* ps = ev.mutable_pipeline_stage();
  ps->set_stage_name(pipeline.get_name());
  ps->set_stage_kind(p4::bm::PipelineStageEvent::CONTROL);
  ps->set_direction(p4::bm::PipelineStageEvent::EXIT);
  trace_add_event(packet, std::move(ev));
}

void PacketTracer::condition_eval(const Packet& packet, const Conditional& cond,
                                  bool result) {
  _BM_UNUSED(packet);
  _BM_UNUSED(cond);
  _BM_UNUSED(result);
}

void PacketTracer::table_hit(const Packet& packet,
                             const MatchTableAbstract& table,
                             entry_handle_t handle) {
  _BM_UNUSED(packet);
  _BM_UNUSED(table);
  _BM_UNUSED(handle);
}

void PacketTracer::table_miss(const Packet& packet,
                              const MatchTableAbstract& table) {
  _BM_UNUSED(packet);
  _BM_UNUSED(table);
}

void PacketTracer::action_execute(const Packet& packet,
                                  const ActionFn& action_fn,
                                  const ActionData& action_data) {
  _BM_UNUSED(packet);
  _BM_UNUSED(action_fn);
  _BM_UNUSED(action_data);
}

void PacketTracer::config_change() {}

}  // namespace bm

#endif  // BM_PACKET_TRACE_ON
