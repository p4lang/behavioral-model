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

extern int import_checksum();

/* Frame (34 bytes) */
static const unsigned char raw_pkt[34] = {
    0x52, 0x54, 0x00, 0x12, 0x35, 0x02, 0x08, 0x00,
    0x27, 0x01, 0x8b, 0xbc, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06,
    0xff, 0xff, 0x0a, 0x00, 0x02, 0x0f, 0x0a, 0x01,
    0x00, 0x01
};

class PSA_ChecksumTest : public ::testing::Test {
 protected:
    HeaderType ethernetHeaderType, ipv4HeaderType;
    ParseState ethernetParseState, ipv4ParseState;
    header_id_t ethernetHeader{0}, ipv4Header{1};

    ErrorCodeMap error_codes;
    Parser parser;

    std::unique_ptr<PHVSourceIface> phv_source{nullptr};

    std::unique_ptr<bm::ExternType> instance{nullptr};

    PHVFactory phv_factory;

    std::unique_ptr<Packet> packet{nullptr};

    PSA_ChecksumTest()
        :   ethernetHeaderType("ethernet_t", 0), ipv4HeaderType("ipv4_t", 1),
            ethernetParseState("parse_ethernet", 0),
            ipv4ParseState("parse_ipv4", 1),
            error_codes(ErrorCodeMap::make_with_core()),
            parser("test_parser", 0, &error_codes),
            phv_source(PHVSourceIface::make_phv_source()),
            instance(ExternFactoryMap::get_instance()->
                    get_extern_instance("Checksum")) {
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

        phv_factory.push_back_header("ethernet", ethernetHeader,
                                    ethernetHeaderType);
        phv_factory.push_back_header("ipv4", ipv4Header, ipv4HeaderType);
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
        instance->_set_attribute<std::string>("hash", "crc16");
        instance->init();

        import_checksum();
    }

    virtual void TearDown() { }
};

static std::unique_ptr<ActionPrimitive_> get_extern_primitive(
    const std::string &extern_name, const std::string &method_name) {
    return ActionOpcodesMap::get_instance()->get_primitive(
        "_" + extern_name + "_" + method_name);
}

TEST_F(PSA_ChecksumTest, PSA_ChecksumMethods) {
    uint16_t cksum;
    auto phv = packet.get()->get_phv();

    // ACTION ADD
    ActionFn actionFn_update("_Checksum_update", 0, 0);
    ActionFnEntry actionFnEntry_update(&actionFn_update);
    auto primitive_update = get_extern_primitive("Checksum", "update");
    ASSERT_NE(nullptr, primitive_update);
    actionFn_update.push_back_primitive(primitive_update.get());
    actionFn_update.parameter_push_back_extern_instance(instance.get());
    actionFn_update.parameter_start_field_list();
    actionFn_update.parameter_push_back_field(ipv4Header, 0);
    actionFn_update.parameter_push_back_field(ipv4Header, 1);
    actionFn_update.parameter_push_back_field(ipv4Header, 2);
    actionFn_update.parameter_push_back_field(ipv4Header, 3);
    actionFn_update.parameter_push_back_field(ipv4Header, 4);
    actionFn_update.parameter_push_back_field(ipv4Header, 5);
    actionFn_update.parameter_push_back_field(ipv4Header, 6);
    actionFn_update.parameter_push_back_field(ipv4Header, 7);
    actionFn_update.parameter_push_back_field(ipv4Header, 8);
    actionFn_update.parameter_push_back_field(ipv4Header, 10);
    actionFn_update.parameter_push_back_field(ipv4Header, 11);
    actionFn_update.parameter_end_field_list();

    // ACTION GET
    ActionFn actionFn_get("_Checksum_get", 0, 0);
    ActionFnEntry actionFnEntry_get(&actionFn_get);
    auto primitive_get = get_extern_primitive("Checksum", "get");
    ASSERT_NE(nullptr, primitive_get);
    actionFn_get.push_back_primitive(primitive_get.get());
    actionFn_get.parameter_push_back_extern_instance(instance.get());
    actionFn_get.parameter_push_back_field(ipv4Header, 9);

    cksum = 0xba50;

    actionFnEntry_update(packet.get());
    actionFnEntry_get(packet.get());
    ASSERT_EQ(cksum, phv->get_field("ipv4.checksum").get<uint16_t>());
}
