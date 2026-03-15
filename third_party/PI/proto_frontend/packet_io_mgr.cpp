/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
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
 * Antonin Bas
 *
 */

#include "packet_io_mgr.h"

#include <algorithm>  // for std::fill, std::copy
#include <string>
#include <unordered_map>
#include <utility>  // for std::move
#include <vector>

#include "google/rpc/code.pb.h"

#include "common.h"
#include "report_error.h"
#include "status_macros.h"

namespace p4v1 = ::p4::v1;
namespace p4configv1 = ::p4::config::v1;
namespace p4serverv1 = ::p4::server::v1;

namespace pi {

namespace fe {

namespace proto {

using Code = ::google::rpc::Code;

using common::bytestring_p4rt_to_pi;
using common::bytestring_pi_to_p4rt;

namespace {

using p4configv1::ControllerPacketMetadata;

size_t compute_nbytes(const ControllerPacketMetadata &metadata_hdr) {
  size_t nbits = 0;
  for (const auto &metadata : metadata_hdr.metadata())
    nbits += metadata.bitwidth();
  return (nbits + 7) / 8;
}

// generic_extract and generic_deparse taken from the behavioral-model code

void generic_extract(const char *data, int bit_offset, int bitwidth,
                     char *dst) {
  int nbytes = (bitwidth + 7) / 8;

  if (bit_offset == 0 && bitwidth % 8 == 0) {
    memcpy(dst, data, nbytes);
    return;
  }

  int dst_offset = (nbytes << 3) - bitwidth;
  int i;

  // necessary to ensure correct behavior when shifting right (no sign
  // extension)
  auto udata = reinterpret_cast<const unsigned char *>(data);

  int offset = bit_offset - dst_offset;
  if (offset == 0) {
    memcpy(dst, udata, nbytes);
    dst[0] &= (0xFF >> dst_offset);
  } else if (offset > 0) {  // shift left
    for (i = 0; i < nbytes - 1; i++) {
      dst[i] = (udata[i] << offset) | (udata[i + 1] >> (8 - offset));
    }
    dst[i] = udata[i] << offset;
    dst[0] &= (0xFF >> dst_offset);
    if ((bit_offset + bitwidth) > (nbytes << 3)) {
      dst[i] |= (udata[i + 1] >> (8 - offset));
    }
  } else {  // shift right
    offset = -offset;
    dst[0] = udata[0] >> offset;
    dst[0] &= (0xFF >> dst_offset);
    for (i = 1; i < nbytes; i++) {
      dst[i] = (udata[i - 1] << (8 - offset)) | (udata[i] >> offset);
    }
  }
}

// Successive calls to generic_deparse must be done in the correct order,
// i.e. according to the order in which the fields are defined in the header.
void generic_deparse(const char *data, int bitwidth, char *dst,
                     int hdr_offset) {
  if (bitwidth == 0) return;

  int nbytes = (bitwidth + 7) / 8;

  if (hdr_offset == 0 && bitwidth % 8 == 0) {
    memcpy(dst, data, nbytes);
    return;
  }

  int field_offset = (nbytes << 3) - bitwidth;
  int hdr_bytes = (hdr_offset + bitwidth + 7) / 8;

  int i;

  // necessary to ensure correct behavior when shifting right (no sign
  // extension)
  auto udata = reinterpret_cast<const unsigned char *>(data);

  // zero out bits we are going to write in dst[0]
  dst[0] &= (~(0xFF >> hdr_offset));

  int offset = field_offset - hdr_offset;
  if (offset == 0) {
    std::copy(data + 1, data + hdr_bytes, dst + 1);
    dst[0] |= udata[0];
  } else if (offset > 0) {  // shift left
    // don't know if this is very efficient, we memset the remaining bytes to 0
    // so we can use |= and preserve what was originally in dst[0]
    std::fill(&dst[1], &dst[hdr_bytes], 0);
    for (i = 0; i < hdr_bytes - 1; i++) {
      dst[i] |= (udata[i] << offset) | (udata[i + 1] >> (8 - offset));
    }
    dst[i] |= udata[i] << offset;
  } else {  // shift right
    offset = -offset;
    dst[0] |= (udata[0] >> offset);
    if (nbytes == 1) {
      // dst[1] is always valid, otherwise we would not need to shift the field
      // to the right
      dst[1] = udata[0] << (8 - offset);
      return;
    }
    for (i = 1; i < hdr_bytes - 1; i++) {
      dst[i] = (udata[i - 1] << (8 - offset)) | (udata[i] >> offset);
    }
    int tail_offset = (hdr_bytes << 3) - (hdr_offset + bitwidth);
    dst[i] &= ((1 << tail_offset) - 1);
    dst[i] |= (udata[i - 1] << (8 - offset));
  }
}

}  // namespace

class PacketInMutate {
 public:
  static constexpr const char name[] = "packet_in";

  explicit PacketInMutate(const ControllerPacketMetadata &metadata_hdr)
      : metadata_hdr(metadata_hdr) {
    nbytes = compute_nbytes(metadata_hdr);
  }

  bool operator ()(const char *pkt, size_t size,
                   p4v1::PacketIn *packet_in) const {
    if (size < nbytes) return false;
    packet_in->set_payload(pkt + nbytes, size - nbytes);
    int bit_offset = 0;
    std::vector<char> buffer(32);
    for (const auto &metadata_info : metadata_hdr.metadata()) {
      auto metadata = packet_in->add_metadata();
      metadata->set_metadata_id(metadata_info.id());
      auto bitwidth = metadata_info.bitwidth();
      buffer.resize((bitwidth + 7) / 8);
      buffer[0] = 0;
      generic_extract(pkt, bit_offset, bitwidth, buffer.data());
      bit_offset += (bitwidth % 8);
      pkt += (bitwidth / 8);
      if (bit_offset >= 8) {
          pkt += (bit_offset / 8);
          bit_offset = bit_offset % 8;
      }
      metadata->set_value(bytestring_pi_to_p4rt(buffer.data(), buffer.size()));
    }
    return true;
  }

 private:
  ControllerPacketMetadata metadata_hdr;
  size_t nbytes{0};
};

constexpr const char PacketInMutate::name[];

namespace {

class Id2Offset {
 public:
  struct Offset {
    int idx;
    int byte_offset;
    int bit_offset;
    int bitwidth;
  };

  using Map = std::unordered_map<uint32_t, Offset>;
  using iterator = Map::iterator;
  using const_iterator = Map::const_iterator;

  explicit Id2Offset(const ControllerPacketMetadata &metadata_hdr) {
    int nbits = 0;
    for (int i = 0; i < metadata_hdr.metadata_size(); i++) {
      const auto &metadata = metadata_hdr.metadata(i);
      auto id = metadata.id();
      auto bitwidth = metadata.bitwidth();
      offsets.emplace(id, Offset{i, nbits / 8, nbits % 8, bitwidth});
      nbits += bitwidth;
    }
  }

  const Offset &at(uint32_t id) const { return offsets.at(id); }

  iterator find(uint32_t id) { return offsets.find(id); }
  const_iterator find(uint32_t id) const { return offsets.find(id); }

  iterator begin() noexcept { return offsets.begin(); }
  const_iterator begin() const noexcept { return offsets.begin(); }

  iterator end() noexcept { return offsets.end(); }
  const_iterator end() const noexcept { return offsets.end(); }

 private:
  Map offsets{};
};

}  // namespace

using Status = PacketIOMgr::Status;

class PacketOutMutate {
 public:
  static constexpr const char name[] = "packet_out";

  explicit PacketOutMutate(const ControllerPacketMetadata &metadata_hdr)
      : metadata_hdr(metadata_hdr), metadata_cnt(metadata_hdr.metadata_size()),
        id2offset(metadata_hdr) {
    nbytes = compute_nbytes(metadata_hdr);
  }

  // TODO(antonin): to be fully conformant to the P4Runtime spec, we should drop
  // the PacketOut message if even one metadata field is missing. It may be a
  // good idea to make this behavior configurable since some clients may rely on
  // the current behavior.
  Status operator ()(const p4v1::PacketOut &packet_out,
                     std::string *pkt) const {
    struct Ptr {
      Ptr() = default;
      Ptr(const Id2Offset::Offset *offset, const std::string *value)
          : offset(offset), value(value) { }

      const Id2Offset::Offset *offset{nullptr};
      const std::string *value{nullptr};
    };
    // We need to do a first pass to order the metadata fields provided by the
    // P4Runtime client, as successive calls to generic_deparse must be done
    // according to the order in which fields are defined in the controller
    // header.
    // In the future, we may want to update the generic_deparse implementation
    // to lift this restriction (if it comes with a performance benefit).
    std::vector<Ptr> ptrs(metadata_cnt);
    for (const auto &metadata : packet_out.metadata()) {
      auto offset_it = id2offset.find(metadata.metadata_id());
      if (offset_it == id2offset.end()) {
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "Unknown metadata id in PacketOut message");
      }
      const auto &offset = offset_it->second;
      ptrs[offset.idx] = Ptr{&offset, &metadata.value()};
    }
    pkt->clear();
    const auto &payload = packet_out.payload();
    pkt->reserve(nbytes + payload.size());
    pkt->append(nbytes, 0);
    for (const auto &ptr : ptrs) {
      if (!ptr.offset) continue;  // missing field in PacketOut message
      ASSIGN_OR_RETURN(
          auto value, bytestring_p4rt_to_pi(*ptr.value, ptr.offset->bitwidth));
      generic_deparse(value.data(), ptr.offset->bitwidth,
                      &(*pkt)[ptr.offset->byte_offset], ptr.offset->bit_offset);
    }
    pkt->append(payload);
    RETURN_OK_STATUS();
  }

 private:
  ControllerPacketMetadata metadata_hdr;
  size_t nbytes{0};
  int metadata_cnt{0};
  Id2Offset id2offset;
};

constexpr const char PacketOutMutate::name[];

PacketIOMgr::PacketIOMgr(device_id_t device_id,
                         ServerConfigAccessor *server_config)
    : device_id(device_id),
      server_config(server_config),
      packet_in_mutate(nullptr),
      packet_out_mutate(nullptr) { }

PacketIOMgr::~PacketIOMgr() = default;

void
PacketIOMgr::p4_change(const p4configv1::P4Info &p4info) {
  PacketInMutate *packet_in_mutate_new = nullptr;
  PacketOutMutate *packet_out_mutate_new = nullptr;
  for (const auto &metadata_hdr : p4info.controller_packet_metadata()) {
    const auto &name = metadata_hdr.preamble().name();
    if (name == PacketInMutate::name)
      packet_in_mutate_new = new PacketInMutate(metadata_hdr);
    else if (name == PacketOutMutate::name)
      packet_out_mutate_new = new PacketOutMutate(metadata_hdr);
  }
  Lock lock(mutex);
  packet_in_mutate.reset(packet_in_mutate_new);
  packet_out_mutate.reset(packet_out_mutate_new);
}

namespace {

void make_stream_error(p4v1::StreamError *stream_error,
                       const p4v1::PacketOut &packet,
                       int code,
                       const std::string &message,
                       bool detailed) {
  stream_error->set_canonical_code(code);
  stream_error->set_message(message);
  stream_error->set_space("ALL-sswitch-p4org");
  auto *details = stream_error->mutable_packet_out();
  if (detailed) details->mutable_packet_out()->CopyFrom(packet);
}

void make_stream_error(p4v1::StreamError *stream_error,
                       const p4v1::PacketOut &packet,
                       const Status &status,
                       bool detailed) {
  make_stream_error(
      stream_error, packet, status.code(), status.message(), detailed);
}

template <typename... Args>
void make_stream_error_if(p4serverv1::StreamConfig::ErrorReportingLevel level,
                          Args &&...args) {
  if (level == p4serverv1::StreamConfig::DISABLED) return;
  make_stream_error(std::forward<Args>(args)...);
}

}  // namespace

Status
PacketIOMgr::packet_out_send(const p4v1::PacketOut &packet) const {
  p4v1::StreamError stream_error;
  return packet_out_send(packet, &stream_error);
}

Status
PacketIOMgr::packet_out_send(const p4v1::PacketOut &packet,
                             p4v1::StreamError *stream_error) const {
  pi_status_t pi_status = PI_STATUS_SUCCESS;
  // TODO(antonin): unify both cases, we could have a mutator (no-op) even when
  // there is no metadata.
  if (packet_out_mutate) {
    std::string raw_packet;
    auto status = (*packet_out_mutate)(packet, &raw_packet);
    if (IS_ERROR(status)) {
      auto error_reporting_level = error_reporting();
      make_stream_error_if(
          error_reporting_level, stream_error, packet, status,
          error_reporting_level == p4serverv1::StreamConfig::DETAILED);
      return status;
    }
    pi_status = pi_packetout_send(device_id, raw_packet.data(),
                                  raw_packet.size());
  } else if (packet.metadata_size() > 0) {  // unexpected metadata
    auto status = ERROR_STATUS(
        Code::INVALID_ARGUMENT, "Unexpected metadata in PacketOut message");
    auto error_reporting_level = error_reporting();
    make_stream_error_if(
        error_reporting_level, stream_error, packet, status,
        error_reporting_level == p4serverv1::StreamConfig::DETAILED);
    return status;
  } else {
    const auto &payload = packet.payload();
    pi_status = pi_packetout_send(device_id, payload.data(),
                                  payload.size());
  }
  if (pi_status != PI_STATUS_SUCCESS) {
    make_stream_error_if(
        error_reporting(), stream_error, packet, Code::UNKNOWN,
        "Unknown error when target sending packet-out", false);
    RETURN_ERROR_STATUS(Code::UNKNOWN);
  }
  RETURN_OK_STATUS();
}

void
PacketIOMgr::packet_in_register_cb(StreamMessageResponseCb cb, void *cookie) {
  cb_ = std::move(cb);
  cookie_ = cookie;
  pi_packetin_register_cb(device_id, &PacketIOMgr::packet_in_cb,
                          static_cast<void *>(this));
}

void
PacketIOMgr::packet_in_cb(pi_dev_id_t dev_id, const char *pkt, size_t size,
                          void *cookie) {
  auto mgr = static_cast<PacketIOMgr *>(cookie);
  assert(dev_id == mgr->device_id);
  p4v1::StreamMessageResponse msg;
  auto *packet_in = msg.mutable_packet();
  if (mgr->packet_in_mutate) {
    Lock lock(mgr->mutex);
    auto success = (*mgr->packet_in_mutate)(pkt, size, packet_in);
    if (!success) return;
  } else {
    packet_in->set_payload(pkt, size);
  }
  mgr->cb_(mgr->device_id, &msg, mgr->cookie_);
}

p4serverv1::StreamConfig::ErrorReportingLevel
PacketIOMgr::error_reporting() const {
  return server_config->get([](
      const p4::server::v1::Config &config) {
          return config.stream().error_reporting(); });
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
