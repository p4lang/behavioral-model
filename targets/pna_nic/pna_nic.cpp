/* Copyright 2024 Marvell Technology, Inc.
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
 * Rupesh Chiluka (rchiluka@marvell.com)
 *
 */

#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/tables.h>
#include <bm/bm_sim/logger.h>

#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>

#include "pna_nic.h"

extern int import_primitives();
extern int import_counters();
extern int import_meters();
extern int import_random();
extern int import_internet_checksum();
extern int import_hash();

namespace bm {

namespace pna {

packet_id_t PnaNic::packet_id = 0;


PnaNic::PnaNic(bool enable_swap)
  : Switch(enable_swap),
    input_buffer(1024),
    output_buffer(128),
    // cannot use std::bind because of a clang bug
    // https://stackoverflow.com/questions/32030141/is-this-incorrect-use-of-stdbind-or-a-compiler-bug
    my_transmit_fn([this](port_t port_num, packet_id_t pkt_id,
                          const char *buffer, int len) {
        _BM_UNUSED(pkt_id);
        this->transmit_fn(port_num, buffer, len);
    }),
    start(clock::now())
    {
  add_required_field("pna_main_parser_input_metadata", "recirculated");
  add_required_field("pna_main_parser_input_metadata", "input_port");

  add_required_field("pna_main_input_metadata", "recirculated");
  add_required_field("pna_main_input_metadata", "timestamp");
  add_required_field("pna_main_input_metadata", "parser_error");
  add_required_field("pna_main_input_metadata", "class_of_service");
  add_required_field("pna_main_input_metadata", "input_port");

  add_required_field("pna_main_output_metadata", "class_of_service");

  force_arith_header("pna_main_parser_input_metadata");
  force_arith_header("pna_main_input_metadata");
  force_arith_header("pna_main_output_metadata");

  import_primitives();
  import_counters();
  import_meters();
  import_random();
  import_internet_checksum();
  import_hash();
}

#define PACKET_LENGTH_REG_IDX 0

int
PnaNic::receive_(port_t port_num, const char *buffer, int len) {
  // we limit the packet buffer to original size + 512 bytes, which means we
  // cannot add more than 512 bytes of header data to the packet, which should
  // be more than enough
  
  auto packet = new_packet_ptr(port_num, packet_id++, len,
                               bm::PacketBuffer(len + 512, buffer, len));

  BMELOG(packet_in, *packet);
  auto *phv = packet->get_phv();

  // many current p4 programs assume this
  // from pna spec - PNA does not mandate initialization of user-defined
  // metadata to known values as given as input to the parser
  phv->reset_metadata();
  
  phv->get_field("pna_main_parser_input_metadata.recirculated").set(0);
  phv->get_field("pna_main_parser_input_metadata.input_port").set(port_num);

  // using packet register 0 to store length, this register will be updated for
  // each add_header / remove_header primitive call
  packet->set_register(PACKET_LENGTH_REG_IDX, len);

  input_buffer.push_front(std::move(packet));
  return 0;
}

void
PnaNic::start_and_return_() {
  threads_.push_back(std::thread(&PnaNic::main_thread, this));
  threads_.push_back(std::thread(&PnaNic::transmit_thread, this));
}

PnaNic::~PnaNic() {
  input_buffer.push_front(nullptr);
  output_buffer.push_front(nullptr);
  for (auto& thread_ : threads_) {
    thread_.join();
  }
}

void
PnaNic::reset_target_state_() {
  bm::Logger::get()->debug("Resetting pna_nic target-specific state");
  get_component<McSimplePreLAG>()->reset_state();
}

uint64_t
PnaNic::get_time_elapsed_us() const {
  return get_ts().count();
}

uint64_t
PnaNic::get_time_since_epoch_us() const {
  auto tp = clock::now();
  return duration_cast<ts_res>(tp.time_since_epoch()).count();
}

void
PnaNic::set_transmit_fn(TransmitFn fn) {
  my_transmit_fn = std::move(fn);
}

void
PnaNic::transmit_thread() {
  while (1) {
    std::unique_ptr<Packet> packet;
    output_buffer.pop_back(&packet);

    if (packet == nullptr) break;
    BMELOG(packet_out, *packet);
    BMLOG_DEBUG_PKT(*packet, "Transmitting packet of size {} out of port {}",
                    packet->get_data_size(), packet->get_egress_port());

    my_transmit_fn(packet->get_egress_port(), packet->get_packet_id(),
                   packet->data(), packet->get_data_size());
  }
}

ts_res
PnaNic::get_ts() const {
  return duration_cast<ts_res>(clock::now() - start);
}

void
PnaNic::main_thread() {
  PHV *phv;

  while (1) {
    std::unique_ptr<Packet> packet;
    input_buffer.pop_back(&packet);
    if (packet == nullptr) break;

    phv = packet->get_phv();
    auto input_port =
        phv->get_field("pna_main_parser_input_metadata.input_port").
            get_uint();
    BMLOG_DEBUG_PKT(*packet, "Processing packet received on port {}",
                    input_port);
                    
    phv->get_field("pna_main_input_metadata.timestamp").set(
        get_ts().count());

    Parser *parser = this->get_parser("main_parser");
    parser->parse(packet.get());

    // pass relevant values from main parser
    phv->get_field("pna_main_input_metadata.recirculated").set(
        phv->get_field("pna_main_parser_input_metadata.recirculated"));
    phv->get_field("pna_main_input_metadata.parser_error").set(
        packet->get_error_code().get());
    phv->get_field("pna_main_input_metadata.class_of_service").set(0);
    phv->get_field("pna_main_input_metadata.input_port").set(
        phv->get_field("pna_main_parser_input_metadata.input_port"));
    
    Pipeline *main_mau = this->get_pipeline("main_control");
    main_mau->apply(packet.get());
    packet->reset_exit();

    Deparser *deparser = this->get_deparser("main_deparser");
    deparser->deparse(packet.get());
    output_buffer.push_front(std::move(packet));
  }
}

}  // namespace bm::pna

}  // namespace bm
