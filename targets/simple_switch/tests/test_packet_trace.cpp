// SPDX-FileCopyrightText: 2026 Yuao Ma
//
// SPDX-License-Identifier: Apache-2.0

// Golden-test runner for the BMv2 structured packet tracer.
//
// Runs an in-process simple_switch instance for one P4 pipeline, injects the
// scenario input packets, and prints the resulting packet traces (and output
// packets) to stdout in a stable, human-reviewable format. The output is
// compared against a checked-in testdata/<pipeline>.trace file by a
// cmd_diff_test Bazel rule.
//
// To regenerate the golden file after an intended behavior change:
//   bazel run //targets/simple_switch/tests:packet_trace_<pipeline>_diff_test
//     -- --update
// With the autotools or CMake build, run tests/run_packet_trace_test.sh with
// BM_UPDATE_GOLDEN=1 instead.
//
// Usage: test_packet_trace <pipeline> <path/to/pipeline.json>

#include <bm/config.h>

#ifndef BM_PACKET_TRACE_ON
#error "test_packet_trace requires BM_PACKET_TRACE_ON"
#endif

#include <bm/bm_sim/dev_mgr.h>
#include <bm/bm_sim/event_observer.h>
#include <bm/bm_sim/packet_tracer.h>
#include <bm/bm_sim/port_monitor.h>
#include <google/protobuf/text_format.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "packet_trace.pb.h"
#include "simple_switch.h"

namespace fs = std::filesystem;

namespace {

using bm::ActionData;
using bm::entry_handle_t;
using bm::MatchErrorCode;
using bm::MatchKeyParam;

constexpr char kSectionBanner[] =
    "=========================================================================";
constexpr char kInputBanner[] =
    "-- INPUT ----------------------------------------------------------------";
constexpr char kOutputBanner[] =
    "-- OUTPUT ---------------------------------------------------------------";

// Formats a raw byte string as lowercase hex, two zero-padded digits per byte
// with no separators (e.g. "\x0a\xbc" -> "0abc"). Used to print packet
// payloads and match keys deterministically in the golden output.
std::string ByteStringToFormatedHexString(const std::string& bytes) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (char c : bytes) {
    auto b = static_cast<unsigned char>(c);
    out.push_back(digits[b >> 4]);
    out.push_back(digits[b & 0xf]);
  }
  return out;
}

// A no-op device manager: the runner injects packets with
// SwitchWContexts::receive() and captures output packets with
// SimpleSwitch::set_transmit_fn(), so no I/O backend is needed. An
// implementation must still be installed because DevMgr::start() requires one.
class DummyDevMgr : public bm::DevMgrIface {
 public:
  DummyDevMgr() { p_monitor = bm::PortMonitorIface::make_dummy(); }

 private:
  ReturnCode port_add_(const std::string& iface_name, port_t port_num,
                       const PortExtras& port_extras) override {
    (void)iface_name;
    (void)port_num;
    (void)port_extras;
    return ReturnCode::SUCCESS;
  }

  ReturnCode port_remove_(port_t port_num) override {
    (void)port_num;
    return ReturnCode::SUCCESS;
  }

  void transmit_fn_(port_t port_num, const char* buffer, int len) override {
    (void)port_num;
    (void)buffer;
    (void)len;
  }

  void start_() override {}

  ReturnCode set_packet_handler_(const PacketHandler& handler,
                                 void* cookie) override {
    (void)handler;
    (void)cookie;
    return ReturnCode::SUCCESS;
  }

  bool port_is_up_(port_t port_num) const override {
    (void)port_num;
    return true;
  }

  std::map<port_t, PortInfo> get_port_info_() const override { return {}; }
};

struct InputPacket {
  bm::port_t port;
  std::string data;
};

struct OutputPacket {
  bm::port_t port;
  std::string data;
};

// Collects the packets transmitted by the switch (registered with
// SimpleSwitch::set_transmit_fn, called from the switch's transmit thread).
class OutputCollector {
 public:
  void record(bm::port_t port, const char* buffer, int len) {
    std::lock_guard<std::mutex> lock(mutex_);
    packets_.push_back({port, std::string(buffer, len)});
    cvar_.notify_all();
  }

  // Waits until at least n packets have been collected since the last take().
  bool wait_for_packets(size_t n, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    return cvar_.wait_for(lock, timeout,
                          [this, n] { return packets_.size() >= n; });
  }

  std::vector<OutputPacket> take() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto packets = std::move(packets_);
    packets_.clear();
    return packets;
  }

 private:
  std::mutex mutex_;
  std::condition_variable cvar_;
  std::vector<OutputPacket> packets_;
};

struct TraceTestCase {
  std::string name;
  std::string description;
  // Programs tables for this case and prints a description of the programming
  // to os (one indented line per operation).
  std::function<void(SimpleSwitch*, std::ostream&)> setup;
  std::vector<InputPacket> inputs;
  size_t expected_outputs;
  // Queueing metadata (timestamps) makes some output payloads
  // non-deterministic; such cases only print output packet sizes.
  bool dump_output_payload = true;
};

// Table-programming helpers: perform the operation and print one line
// describing it. Errors are printed to stdout so that they break the golden
// diff instead of going unnoticed.
void set_default_action(SimpleSwitch* sw, std::ostream& os,
                        const std::string& table, const std::string& action,
                        const std::vector<unsigned>& args = {}) {
  ActionData data;
  std::string printed_args;
  for (auto arg : args) {
    data.push_back_action_data(arg);
    if (!printed_args.empty()) printed_args += ", ";
    printed_args += std::to_string(arg);
  }
  auto rc = sw->mt_set_default_action(0, table, action, std::move(data));
  os << "  " << table << ": set default action " << action << "("
     << printed_args << ")\n";
  if (rc != MatchErrorCode::SUCCESS) {
    os << "  ERROR: mt_set_default_action failed for table " << table << ": "
       << bm::match_error_code_to_string(rc) << "\n";
  }
}

void add_exact_entry(SimpleSwitch* sw, std::ostream& os,
                     const std::string& table,
                     const std::vector<std::string>& key,
                     const std::string& action,
                     const std::vector<unsigned>& args = {}) {
  std::vector<MatchKeyParam> match_key;
  std::string printed_key;
  for (const auto& field : key) {
    match_key.emplace_back(MatchKeyParam::Type::EXACT, field);
    if (!printed_key.empty()) printed_key += ", ";
    printed_key += "0x" + ByteStringToFormatedHexString(field);
  }
  ActionData data;
  std::string printed_args;
  for (auto arg : args) {
    data.push_back_action_data(arg);
    if (!printed_args.empty()) printed_args += ", ";
    printed_args += std::to_string(arg);
  }
  entry_handle_t handle;
  auto rc =
      sw->mt_add_entry(0, table, match_key, action, std::move(data), &handle);
  os << "  " << table << ": add entry [" << printed_key << "] => " << action
     << "(" << printed_args << ")\n";
  if (rc != MatchErrorCode::SUCCESS) {
    os << "  ERROR: mt_add_entry failed for table " << table << ": "
       << bm::match_error_code_to_string(rc) << "\n";
  }
}

// Reads all trace files from dir, keyed by the global packet id recorded in
// the trace (so iteration order is numeric injection order, not lexicographic
// file-name order). Only files that parse as a complete p4::bm::PacketTrace
// textproto are kept (a file may be observed mid-write since traces are
// flushed from the switch's processing threads).
std::map<uint64_t, p4::bm::PacketTrace> read_traces(const fs::path& dir) {
  std::map<uint64_t, p4::bm::PacketTrace> traces;
  std::error_code ec;
  for (const auto& entry : fs::directory_iterator(dir, ec)) {
    std::ifstream in(entry.path());
    if (!in.is_open()) continue;
    std::stringstream ss;
    ss << in.rdbuf();
    p4::bm::PacketTrace trace;
    if (google::protobuf::TextFormat::ParseFromString(ss.str(), &trace)) {
      traces[trace.input().packet_id()] = std::move(trace);
    }
  }
  return traces;
}

// Traces are flushed when the switch destroys a packet, which happens shortly
// *after* the corresponding output packet (if any) is transmitted, so the
// trace files may not exist yet when the output packets have all been
// collected. Each input packet produces exactly one trace file (clones and
// recirculated copies attach to the same recursive trace), so poll until
// `expected` files parse or the timeout expires.
std::map<uint64_t, p4::bm::PacketTrace> wait_for_traces(const fs::path& dir,
                                                        size_t expected) {
  using clock = std::chrono::steady_clock;
  const auto deadline = clock::now() + std::chrono::seconds(5);
  auto traces = read_traces(dir);
  while (traces.size() < expected && clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    traces = read_traces(dir);
  }
  return traces;
}

void run_case(SimpleSwitch* sw, OutputCollector* collector,
              const std::string& pipeline, const TraceTestCase& test_case,
              const fs::path& trace_dir) {
  std::cout << kSectionBanner << "\n"
            << "Packet trace test: " << pipeline << ": " << test_case.name
            << "\n"
            << test_case.description << "\n"
            << kSectionBanner << "\n";

  std::cout << kInputBanner << "\n";
  std::cout << "P4 pipeline: " << pipeline << ".json\n";
  sw->reset_state();
  std::cout << "Table programming (runtime only; config-baked defaults not "
               "shown):\n";
  if (test_case.setup) {
    test_case.setup(sw, std::cout);
  } else {
    std::cout << "  (none)\n";
  }
  std::cout << "Input packets:\n";
  for (const auto& input : test_case.inputs) {
    std::cout << "  port=" << input.port << " len=" << input.data.size()
              << " bytes=" << ByteStringToFormatedHexString(input.data) << "\n";
  }

  bm::PacketTracer::get()->set_output_dir(trace_dir.string());
  for (const auto& input : test_case.inputs) {
    sw->receive(input.port, input.data.data(),
                static_cast<int>(input.data.size()));
  }

  if (!collector->wait_for_packets(test_case.expected_outputs,
                                   std::chrono::seconds(3))) {
    std::cout << "ERROR: timed out waiting for output packets\n";
  }
  auto traces = wait_for_traces(trace_dir, test_case.inputs.size());
  auto outputs = collector->take();

  std::cout << kOutputBanner << "\n";
  std::cout << "Output packets:\n";
  if (outputs.empty()) std::cout << "  (none)\n";
  for (const auto& output : outputs) {
    std::cout << "  port=" << output.port << " len=" << output.data.size();
    if (test_case.dump_output_payload) {
      std::cout << " bytes=" << ByteStringToFormatedHexString(output.data);
    } else {
      std::cout << " (payload not shown: non-deterministic)";
    }
    std::cout << "\n";
  }
  // The golden output renumbers traces 0..N-1 within each case, in packet-id
  // (= injection) order, so trace k is the trace of inputs[k]. The global
  // packet id is deliberately not printed: it depends on how many packets
  // earlier cases injected, and letting it through would churn later cases'
  // golden sections whenever an earlier case changes.
  std::cout << "Packet traces: " << traces.size() << "\n";
  if (traces.empty()) std::cout << "  (none)\n";
  uint64_t index = 0;
  for (auto& [packet_id, trace] : traces) {
    trace.mutable_input()->set_packet_id(index);
    std::string txtpb;
    google::protobuf::TextFormat::PrintToString(trace, &txtpb);
    std::cout << "--- trace " << index << "\n" << txtpb;
    index++;
  }
  std::cout << "\n";
}

std::vector<TraceTestCase> queueing_cases() {
  return {TraceTestCase{
      "unicast forward",
      "A packet is forwarded from port 1 to port 2; the egress pipeline "
      "appends a header with queueing metadata.",
      [](SimpleSwitch* sw, std::ostream& os) {
        set_default_action(sw, os, "t_ingress", "set_port", {2});
        set_default_action(sw, os, "t_egress", "copy_queueing_data");
      },
      {InputPacket{1, std::string(64, '\0')}},
      1,
      // The appended header contains enqueue/dequeue timestamps.
      /*dump_output_payload=*/false,
  }};
}

// recirc.p4 bakes both tables' default actions (loopback, recirc) into the
// config, and its keyless tables cannot take entries (bmv2 returns
// NO_TABLE_KEY), so there is nothing to program at runtime.
std::vector<TraceTestCase> recirc_cases() {
  return {TraceTestCase{
      "recirculate once",
      "A 1-byte packet with value 0x00 is recirculated by the egress "
      "pipeline, so it enters the ingress and egress pipelines twice: the "
      "config-baked default actions run t_loopback on both passes and "
      "t_recirc only on the first (the egress conditional is false once "
      "hdrA1.f1 is 0x01). The second pass is proven by the output: "
      "re-parsing the recirculated 2-byte packet rewrites hdrA2.f1 to 0xab. "
      "The recirculated packet copy currently produces no additional trace "
      "events.",
      nullptr,
      {InputPacket{1, std::string(1, '\0')}},
      1,
  }};
}

std::vector<TraceTestCase> truncate_cases() {
  return {TraceTestCase{
      "truncate to 32 bytes",
      "A 128-byte packet matches an entry that truncates it to 32 bytes and "
      "forwards it to port 2.",
      [](SimpleSwitch* sw, std::ostream& os) {
        add_exact_entry(sw, os, "t_ingress", {std::string(1, '\x01')},
                        "_truncate", {32, 2});
      },
      {InputPacket{1, std::string(1, '\x01') + std::string(127, '\xab')}},
      1,
  }};
}

std::vector<TraceTestCase> parser_error_cases() {
  return {
      TraceTestCase{
          "no parser error",
          "A 4-byte packet parses without error; the error code (0) is "
          "written to the last header byte.",
          nullptr,
          {InputPacket{1, std::string(4, '\0')}},
          1,
      },
      TraceTestCase{
          "packet too short",
          "A 2-byte packet triggers a PacketTooShort parser error; the "
          "ingress pipeline makes the header valid and writes error code 1.",
          nullptr,
          {InputPacket{1, std::string(2, '\0')}},
          1,
      },
      TraceTestCase{
          "custom parser error",
          "The last byte (0xab) triggers a verify() failure with a custom "
          "error, reported as error code 2.",
          nullptr,
          {InputPacket{1, std::string(3, '\0') + std::string(1, '\xab')}},
          1,
      },
  };
}

std::vector<TraceTestCase> packet_redirect_cases() {
  return {TraceTestCase{
      "baseline unicast",
      "The packet hits t_ingress_1 (_set_port to port 2), misses t_ingress_2 "
      "and t_egress (their config-baked NoAction default is a no-op), and is "
      "emitted on port 2 with hdrA.f2 rewritten to the packet length by "
      "t_exit's programmed set_hdr default.",
      [](SimpleSwitch* sw, std::ostream& os) {
        set_default_action(sw, os, "t_exit", "set_hdr");
        add_exact_entry(sw, os, "t_ingress_1",
                        {std::string(1, '\x01'), std::string(1, '\0')},
                        "_set_port", {2});
      },
      {InputPacket{1, std::string(1, '\x01') + std::string(3, '\0')}},
      1,
  }};
}

std::vector<TraceTestCase> cases_for_pipeline(const std::string& pipeline) {
  if (pipeline == "queueing") return queueing_cases();
  if (pipeline == "recirc") return recirc_cases();
  if (pipeline == "truncate") return truncate_cases();
  if (pipeline == "parser_error") return parser_error_cases();
  if (pipeline == "packet_redirect") return packet_redirect_cases();
  return {};
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <pipeline> <path/to/pipeline.json>"
              << "\n";
    return 1;
  }
  const std::string pipeline(argv[1]);
  const std::string json_path(argv[2]);

  auto cases = cases_for_pipeline(pipeline);
  if (cases.empty()) {
    std::cerr << "ERROR: unknown pipeline '" << pipeline << "'\n";
    return 1;
  }

  const char* test_tmpdir = std::getenv("TEST_TMPDIR");
  const fs::path tmp_base =
      (test_tmpdir != nullptr ? fs::path(test_tmpdir)
                              : fs::temp_directory_path()) /
      ("bm_packet_trace_golden_" + std::to_string(::getpid()));

  auto sw = std::make_unique<SimpleSwitch>();
  if (sw->init_objects(json_path) != 0) {
    std::cerr << "ERROR: failed to load P4 pipeline config " << json_path
              << "\n";
    return 1;
  }
  sw->set_dev_mgr(std::make_unique<DummyDevMgr>());
  OutputCollector collector;
  sw->set_transmit_fn([&collector](bm::port_t port, bm::packet_id_t packet_id,
                                   const char* buffer, int len) {
    (void)packet_id;
    collector.record(port, buffer, len);
  });
  bm::EventObserverRegistry::get()->register_observer(bm::PacketTracer::get());
  sw->start_and_return();

  for (size_t i = 0; i < cases.size(); i++) {
    run_case(sw.get(), &collector, pipeline, cases[i],
             tmp_base / ("case_" + std::to_string(i)));
  }

  sw.reset();
  std::error_code ec;
  fs::remove_all(tmp_base, ec);
  return 0;
}
