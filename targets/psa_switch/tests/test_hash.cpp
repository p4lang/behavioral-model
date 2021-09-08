/* Copyright 2021 SYRMIA LLC
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
 * Dusan Krdzic (dusan.krdzic@syrmia.com)
 *
 */

#include <gtest/gtest.h>

#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/phv_source.h>
#include <bm/bm_sim/phv.h>
#include <bm/bm_sim/actions.h>
#include <bm/bm_sim/extern.h>

using namespace bm;

extern int import_hash();

/* Frame (34 bytes) */
static const unsigned char raw_pkt[34] = {
    0x52, 0x54, 0x00, 0x12, 0x35, 0x02, 0x08, 0x00,
    0x27, 0x01, 0x8b, 0xbc, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06,
    0xff, 0xff, 0x0a, 0x00, 0x02, 0x0f, 0x0a, 0x01,
    0x00, 0x01
};

class PSA_HashTest : public ::testing::Test {
 protected:
    HeaderType ethernetHeaderType, ipv4HeaderType;
    HeaderType metaHeaderType;
    ParseState ethernetParseState, ipv4ParseState;
    header_id_t ethernetHeader{0}, ipv4Header{1};
    header_id_t metaHeader{2};

    ErrorCodeMap error_codes;
    Parser parser;

    std::unique_ptr<PHVSourceIface> phv_source{nullptr};

    std::unique_ptr<bm::ExternType> instance{nullptr};

    PHVFactory phv_factory;

    std::unique_ptr<Packet> packet{nullptr};

    PSA_HashTest()
        :   ethernetHeaderType("ethernet_t", 0), ipv4HeaderType("ipv4_t", 1),
            metaHeaderType("meta_t", 2),
            ethernetParseState("parse_ethernet", 0),
            ipv4ParseState("parse_ipv4", 1),
            error_codes(ErrorCodeMap::make_with_core()),
            parser("test_parser", 0, &error_codes),
            phv_source(PHVSourceIface::make_phv_source()),
            instance(ExternFactoryMap::get_instance()->
                    get_extern_instance("Hash")) {
        ethernetHeaderType.push_back_field("dstAddr", 48);
        ethernetHeaderType.push_back_field("srcAddr", 48);
        ethernetHeaderType.push_back_field("ethertype", 16);

        ipv4HeaderType.push_back_field("version", 4);
        ipv4HeaderType.push_back_field("ihl", 4);
        ipv4HeaderType.push_back_field("diffserv", 8);
        ipv4HeaderType.push_back_field("len", 16);
        ipv4HeaderType.push_back_field("id", 16);
        ipv4HeaderType.push_back_field("flags", 3);
        ipv4HeaderType.push_back_field("flagOffset", 13);
        ipv4HeaderType.push_back_field("ttl", 8);
        ipv4HeaderType.push_back_field("protocol", 8);
        ipv4HeaderType.push_back_field("checksum", 16);
        ipv4HeaderType.push_back_field("srcAddr", 32);
        ipv4HeaderType.push_back_field("dstAddr", 32);

        metaHeaderType.push_back_field("input", 12);
        metaHeaderType.push_back_field("dst", 16);
        metaHeaderType.push_back_field("padding", 4);

        phv_factory.push_back_header("ethernet", ethernetHeader,
                                    ethernetHeaderType);
        phv_factory.push_back_header("ipv4", ipv4Header, ipv4HeaderType);
        phv_factory.push_back_header("meta", metaHeader, metaHeaderType, true);
    }

    virtual void SetUp() {
        phv_source->set_phv_factory(0, &phv_factory);

        ParseSwitchKeyBuilder ethernetKeyBuilder;
        ethernetKeyBuilder.push_back_field(ethernetHeader, 2, 16);  // ethertype
        ethernetParseState.set_key_builder(ethernetKeyBuilder);

        ParseSwitchKeyBuilder ipv4KeyBuilder;
        ipv4KeyBuilder.push_back_field(ipv4Header, 8, 8);  // protocol
        ipv4ParseState.set_key_builder(ipv4KeyBuilder);

        ethernetParseState.add_extract(ethernetHeader);
        ipv4ParseState.add_extract(ipv4Header);

        char ethernet_ipv4_key[2];
        ethernet_ipv4_key[0] = 0x08;
        ethernet_ipv4_key[1] = 0x00;
        ethernetParseState.add_switch_case(sizeof(ethernet_ipv4_key),
                                        ethernet_ipv4_key, &ipv4ParseState);

        parser.set_init_state(&ethernetParseState);

        packet = std::unique_ptr<Packet>(new Packet(Packet::make_new(
                                        sizeof(raw_pkt),
                                        PacketBuffer(34, (const char *) raw_pkt,
                                        sizeof(raw_pkt)), phv_source.get())));
        parser.parse(packet.get());

        instance.get()->_register_attributes();
        instance->_set_attribute<std::string>("algo", "crc16");
        instance->init();

        import_hash();
    }

    virtual void TearDown() { }
};

static std::unique_ptr<ActionPrimitive_> get_extern_primitive(
    const std::string &extern_name, const std::string &method_name) {
    return ActionOpcodesMap::get_instance()->get_primitive(
        "_" + extern_name + "_" + method_name);
}

TEST_F(PSA_HashTest, PSA_HashMethods) {
    uint16_t hash;
    auto phv = packet.get()->get_phv();

    // ACTION get_hash
    ActionFn actionFn_gh("_Hash_get_hash", 0, 0);
    ActionFnEntry actionFnEntry_gh(&actionFn_gh);
    auto primitive_gh = get_extern_primitive("Hash", "get_hash");
    ASSERT_NE(nullptr, primitive_gh);
    actionFn_gh.push_back_primitive(primitive_gh.get());
    actionFn_gh.parameter_push_back_extern_instance(instance.get());
    actionFn_gh.parameter_push_back_field(ipv4Header, 9);
    actionFn_gh.parameter_start_field_list();
    actionFn_gh.parameter_push_back_field(ipv4Header, 0);
    actionFn_gh.parameter_push_back_field(ipv4Header, 1);
    actionFn_gh.parameter_push_back_field(ipv4Header, 2);
    actionFn_gh.parameter_push_back_field(ipv4Header, 3);
    actionFn_gh.parameter_push_back_field(ipv4Header, 4);
    actionFn_gh.parameter_push_back_field(ipv4Header, 5);
    actionFn_gh.parameter_push_back_field(ipv4Header, 6);
    actionFn_gh.parameter_push_back_field(ipv4Header, 7);
    actionFn_gh.parameter_push_back_field(ipv4Header, 8);
    actionFn_gh.parameter_push_back_field(ipv4Header, 10);
    actionFn_gh.parameter_push_back_field(ipv4Header, 11);
    actionFn_gh.parameter_end_field_list();

    // ACTION get_hash_mod
    ActionFn actionFn_ghm("_Hash_get_hash_mod", 0, 0);
    ActionFnEntry actionFnEntry_ghm(&actionFn_ghm);
    auto primitive_ghm = get_extern_primitive("Hash", "get_hash_mod");
    ASSERT_NE(nullptr, primitive_ghm);
    actionFn_ghm.push_back_primitive(primitive_ghm.get());
    actionFn_ghm.parameter_push_back_extern_instance(instance.get());
    actionFn_ghm.parameter_push_back_field(ipv4Header, 9);
    actionFn_ghm.parameter_push_back_const(Data("0x06"));
    actionFn_ghm.parameter_start_field_list();
    actionFn_ghm.parameter_push_back_field(ipv4Header, 0);
    actionFn_ghm.parameter_push_back_field(ipv4Header, 1);
    actionFn_ghm.parameter_push_back_field(ipv4Header, 2);
    actionFn_ghm.parameter_push_back_field(ipv4Header, 3);
    actionFn_ghm.parameter_push_back_field(ipv4Header, 4);
    actionFn_ghm.parameter_push_back_field(ipv4Header, 5);
    actionFn_ghm.parameter_push_back_field(ipv4Header, 6);
    actionFn_ghm.parameter_push_back_field(ipv4Header, 7);
    actionFn_ghm.parameter_push_back_field(ipv4Header, 8);
    actionFn_ghm.parameter_push_back_field(ipv4Header, 10);
    actionFn_ghm.parameter_push_back_field(ipv4Header, 11);
    actionFn_ghm.parameter_end_field_list();
    actionFn_ghm.parameter_push_back_const(Data("0x0A"));

    hash = 0xba50;
    actionFnEntry_gh(packet.get());
    ASSERT_EQ(hash, phv->get_field("ipv4.checksum").get<uint16_t>());

    hash = 0x0c;
    actionFnEntry_ghm(packet.get());
    ASSERT_EQ(hash, phv->get_field("ipv4.checksum").get<uint16_t>());

    // ACTION get_hash 2
    ActionFn actionFn_gh2("_Hash_get_hash", 0, 0);
    ActionFnEntry actionFnEntry_gh2(&actionFn_gh2);
    auto primitive_gh2 = get_extern_primitive("Hash", "get_hash");
    ASSERT_NE(nullptr, primitive_gh2);
    actionFn_gh2.push_back_primitive(primitive_gh2.get());
    actionFn_gh2.parameter_push_back_extern_instance(instance.get());
    actionFn_gh2.parameter_push_back_field(metaHeader, 1);
    actionFn_gh2.parameter_start_field_list();
    actionFn_gh2.parameter_push_back_field(metaHeader, 0);
    actionFn_gh2.parameter_end_field_list();

    phv->get_field("meta.input").set(0x456);
    hash = 0xfe82;
    actionFnEntry_gh2(packet.get());
    ASSERT_EQ(hash, phv->get_field("meta.dst").get<uint16_t>());
}
