// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <vector>
#include <string>
#include <iostream>
#include <memory>

#include <boost/filesystem.hpp>

#include "stress_utils.h"

using ::stress_tests_utils::SwitchTest;
using ::stress_tests_utils::TestChrono;

namespace fs = boost::filesystem;

int main(int argc, char* argv[]) {
  size_t num_repeats = 1000;
  if (argc > 1) num_repeats = std::stoul(argv[1]);

  SwitchTest sw;
  fs::path config_path =
      fs::path(TESTDATADIR) / fs::path("parser_deparser_1.json");
  sw.init_objects(config_path.string());

  fs::path traffic_path =
      fs::path(TESTDATADIR) / fs::path("udp_tcp_traffic.bin");
  auto packets = sw.read_traffic(traffic_path.string());

  auto parser = sw.get_parser("parser");
  auto deparser = sw.get_deparser("deparser");

  size_t packet_cnt = packets.size();
  TestChrono chrono(packet_cnt * num_repeats);
  chrono.start();
  for (size_t iter = 0; iter < num_repeats; iter++) {
    for (size_t p = 0; p < packet_cnt; p++) {
      auto pkt = packets[p].get();
      parser->parse(pkt);
      deparser->deparse(pkt);
      // need to reset headers (i.e. mark them invalid) since we are re-using
      // the same Packet objects
      pkt->get_phv()->reset();
    }
  }
  chrono.end();
  chrono.print_summary();
}
