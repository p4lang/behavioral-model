/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <netinet/in.h>

#include <boost/filesystem.hpp>

#include <vector>
#include <string>
#include <iostream>
#include <memory>

#include <cassert>

#include "stress_utils.h"

using ::stress_tests_utils::SwitchTest;
using ::stress_tests_utils::TestChrono;
using ::stress_tests_utils::RandomGen;

namespace fs = boost::filesystem;

namespace {

RandomGen *rgen_ptr;

struct ethernet_t {
  char dstAddr[6];
  char srcAddr[6];
  uint16_t etherType;
} __attribute__((packed));

// not sure how good these entries are...

// we want to favor small prefixes, minimum prefix length is 4
int get_pLen() {
  int pLen = 4;
  while (pLen <= 40) {
    int r = rgen_ptr->get_int(0, 12);
    if (r <= 8) {
      pLen += r;
      return pLen;
    }
    pLen += 8;
  }
  return pLen;
}

bm::MatchErrorCode add_entry_1(SwitchTest *sw, const ethernet_t &hdr) {
  bm::entry_handle_t handle;
  std::vector<bm::MatchKeyParam> match_key;
  match_key.emplace_back(bm::MatchKeyParam::Type::LPM,
                         std::string(hdr.dstAddr, sizeof(hdr.dstAddr)),
                         get_pLen());
  return sw->mt_add_entry(0, "LPM_1", match_key, "_nop", bm::ActionData(),
                          &handle);
}

bm::MatchErrorCode add_entry_2(SwitchTest *sw, const ethernet_t &hdr) {
  bm::entry_handle_t handle;
  std::vector<bm::MatchKeyParam> match_key;
  match_key.emplace_back(bm::MatchKeyParam::Type::LPM,
                         std::string(hdr.srcAddr, sizeof(hdr.srcAddr)),
                         get_pLen());
  return sw->mt_add_entry(0, "LPM_2", match_key, "_nop", bm::ActionData(),
                          &handle);
}

bm::MatchErrorCode add_entry_3(SwitchTest *sw, const ethernet_t &hdr) {
  bm::entry_handle_t handle;
  std::vector<bm::MatchKeyParam> match_key;
  match_key.emplace_back(bm::MatchKeyParam::Type::LPM,
                         std::string(hdr.srcAddr, sizeof(hdr.srcAddr)),
                         get_pLen());
  match_key.emplace_back(bm::MatchKeyParam::Type::EXACT,
                         std::string(hdr.dstAddr, sizeof(hdr.dstAddr)));
  return sw->mt_add_entry(0, "LPM_3", match_key, "_nop", bm::ActionData(),
                          &handle);
}

void check_rc(bm::MatchErrorCode rc) {
  _BM_UNUSED(rc);
  assert(rc == bm::MatchErrorCode::SUCCESS ||
         rc == bm::MatchErrorCode::DUPLICATE_ENTRY);
}

}  // namespace

int main(int argc, char* argv[]) {
  size_t num_repeats = 1000;
  if (argc > 1) num_repeats = std::stoul(argv[1]);

  SwitchTest sw;
  fs::path config_path =
      fs::path(TESTDATADIR) / fs::path("LPM_match_1.json");
  sw.init_objects(config_path.string());

  fs::path traffic_path =
      fs::path(TESTDATADIR) / fs::path("udp_tcp_traffic.bin");
  auto packets = sw.read_traffic(traffic_path.string());

  // populate tables
  RandomGen rgen;
  rgen_ptr = &rgen;
  for (const auto &pkt : packets) {
    ethernet_t *hdr = reinterpret_cast<ethernet_t *>(pkt->data());
    assert(ntohs(hdr->etherType) == 0x0800);  // check for IPv4 ethertype
    check_rc(add_entry_1(&sw, *hdr));
    check_rc(add_entry_2(&sw, *hdr));
    check_rc(add_entry_3(&sw, *hdr));
  }

  auto parser = sw.get_parser("parser");
  auto ingress = sw.get_pipeline("ingress");
  // we have to deparse given that we use the same Packet multiple times
  auto deparser = sw.get_deparser("deparser");

  size_t packet_cnt = packets.size();
  TestChrono chrono(packet_cnt * num_repeats);
  chrono.start();
  for (size_t iter = 0; iter < num_repeats; iter++) {
    for (size_t p = 0; p < packet_cnt; p++) {
      auto pkt = packets[p].get();
      parser->parse(pkt);
      ingress->apply(pkt);
      deparser->deparse(pkt);
      // need to reset headers (i.e. mark them invalid) since we are re-using
      // the same Packet objects
      pkt->get_phv()->reset();
    }
  }
  chrono.end();
  chrono.print_summary();
}
