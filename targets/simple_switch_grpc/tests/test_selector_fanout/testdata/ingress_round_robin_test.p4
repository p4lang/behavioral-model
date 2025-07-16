/* Copyright 2025 Contributors to the P4 Project
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

#include <core.p4>
#include <v1model.p4>

typedef bit<9> PortId_t;

header hdr_t {
    bit<8> in_;
    bit<8> hash_val;
    bit<8> f1;
    bit<8> f2;
    bit<8> f3;
}

struct Headers {
    hdr_t hdr;
}

struct metadata {}

parser p(packet_in b, out Headers h,
         inout metadata m, inout standard_metadata_t sm) {
    state start {
        b.extract(h.hdr);
        transition accept;
    }
}

control vrfy(inout Headers h, inout metadata m) { apply {} }
control update(inout Headers h, inout metadata m) { apply {} }

control egress(inout Headers h, inout metadata m, inout standard_metadata_t sm) {
    apply {}
}

control deparser(packet_out b, in Headers h) {
    apply { b.emit(h); }
}

control ingress(inout Headers h,
                 inout metadata meta,
                 inout standard_metadata_t stdmeta)
{
    @name(".foo1")
    action foo1(bit<8> val, PortId_t port) {
        h.hdr.f1 = val;
        stdmeta.egress_spec = port;
    }
    @name(".foo2")
    action foo2(bit<8> val, PortId_t port) {
        h.hdr.f2 = val;
        stdmeta.egress_spec = port;
    }
    @name(".foo3")
    action foo3(bit<8> val, PortId_t port) {
        h.hdr.f3 = val;
        stdmeta.egress_spec = port;
    }
    @name(".selector_tbl") 
    table selector_tbl {
        actions = {
            foo1;
            foo2;
            foo3;
        }
        key = {
            h.hdr.in_ : exact;
            h.hdr.hash_val : selector;
        }
        size = 16;
        @name(".rr_selector") implementation =
            action_selector(HashAlgorithm.selector_fanout, 16, 4);
    }
    apply {
        selector_tbl.apply();
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
