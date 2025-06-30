// Copyright 2017 Andy Fingerhut
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#include <core.p4>
#include <v1model.p4>

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// IPv4 header _with_ options
header ipv4_t {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      totalLen;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      fragOffset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdrChecksum;
    IPv4Address  srcAddr;
    IPv4Address  dstAddr;
    varbit<320>  options;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header IPv4_up_to_ihl_only_h {
    bit<4>       version;
    bit<4>       ihl;
}

struct headers {
    ethernet_t    ethernet;
    ipv4_t        ipv4;
    tcp_t         tcp;
}

struct mystruct1_t {
    bit<4>  a;
    bit<4>  b;
}

struct metadata {
    mystruct1_t mystruct1;
    bit<16> hash1;
}

// Declare user-defined errors that may be signaled during parsing
error {
    IPv4HeaderTooShort,
    IPv4IncorrectVersion,
    IPv4ChecksumError
}

parser parserI(packet_in pkt,
               out headers hdr,
               inout metadata meta,
               inout standard_metadata_t stdmeta)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        // The 4-bit IHL field of the IPv4 base header is the number
        // of 32-bit words in the entire IPv4 header.  It is an error
        // for it to be less than 5.  There are only IPv4 options
        // present if the value is at least 6.  The length of the IPv4
        // options alone, without the 20-byte base header, is thus ((4
        // * ihl) - 20) bytes, or 8 times that many bits.
        pkt.extract(hdr.ipv4,
                    (bit<32>)
                    (8 *
                     (4 * (bit<9>) (pkt.lookahead<IPv4_up_to_ihl_only_h >().ihl)
                      - 20)));
        verify(hdr.ipv4.version == 4w4, error.IPv4IncorrectVersion);
        verify(hdr.ipv4.ihl >= 4w5, error.IPv4HeaderTooShort);
        transition select (hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

control cIngress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t stdmeta)
{
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action multicast() {
        standard_metadata.mcast_grp = 1;
    }

    action mac_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action foo1(IPv4Address dstAddr) {
        hdr.ipv4.dstAddr = dstAddr;
    }
    action foo2(IPv4Address srcAddr) {
        hdr.ipv4.srcAddr = srcAddr;
    }

    table mac_lookup {
        key = {
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            multicast;
            mac_forward;
            drop;
        }
        size = 8;
        default_action = multicast;
    }

    table rr {
        actions = {
            foo1;
            foo2;
        }
        key = {
            hdr.tcp.srcPort : exact;
            meta.hash1      : selector;
        }
        size = 16;
        implementation =
            action_selector(HashAlgorithm.round_robin, 16, 4);
    }
    apply {
        mac_lookup.apply();
        meta.hash1 = 123; 
        rr.apply();
    }
}

control cEgress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t stdmeta)
{
    apply { }
}

control vc(inout headers hdr,
           inout metadata meta)
{
    apply { }
}

control uc(inout headers hdr,
           inout metadata meta)
{
    apply { }
}

control DeparserI(packet_out packet,
                  in headers hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

V1Switch<headers, metadata>(parserI(),
                            vc(),
                            cIngress(),
                            cEgress(),
                            uc(),
                            DeparserI()) main;