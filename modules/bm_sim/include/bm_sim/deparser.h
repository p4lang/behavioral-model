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

#ifndef BM_SIM_INCLUDE_BM_SIM_DEPARSER_H_
#define BM_SIM_INCLUDE_BM_SIM_DEPARSER_H_

#include <vector>
#include <string>

#include "phv.h"
#include "packet.h"
#include "event_logger.h"
#include "named_p4object.h"
#include "checksums.h"

class Deparser : public NamedP4Object {
 public:
  Deparser(const std::string &name, p4object_id_t id)
    : NamedP4Object(name, id) {}

  void push_back_header(header_id_t header_id) {
    headers.push_back(header_id);
  }

  void add_checksum(const Checksum *checksum) {
    checksums.push_back(checksum);
  }

  size_t get_headers_size(const PHV &phv) const;

  void deparse(Packet *pkt) const;

 private:
  void update_checksums(Packet *pkt) const;

 private:
  std::vector<header_id_t> headers{};
  std::vector<const Checksum *> checksums{};
};

#endif  // BM_SIM_INCLUDE_BM_SIM_DEPARSER_H_
