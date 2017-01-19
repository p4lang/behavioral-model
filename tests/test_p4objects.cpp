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

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <bm/bm_sim/P4Objects.h>

#include <fstream>
#include <sstream>
#include <string>
#include <set>

#include "jsoncpp/json.h"

using namespace bm;

namespace fs = boost::filesystem;

/* I need to find a better way to test the json parser, maybe I could simply
   read from the target files... */

// NOLINTNEXTLINE(whitespace/line_length)
const std::string JSON_TEST_STRING_1 = "{\"header_types\":[{\"name\":\"standard_metadata_t\",\"id\":0,\"fields\":[[\"ingress_port\",9],[\"packet_length\",32],[\"egress_spec\",9],[\"egress_port\",9],[\"egress_instance\",32],[\"instance_type\",32],[\"clone_spec\",32],[\"_padding\",5]]},{\"name\":\"ethernet_t\",\"id\":1,\"fields\":[[\"dstAddr\",48],[\"srcAddr\",48],[\"etherType\",16]]},{\"name\":\"ipv4_t\",\"id\":2,\"fields\":[[\"version\",4],[\"ihl\",4],[\"diffserv\",8],[\"totalLen\",16],[\"identification\",16],[\"flags\",3],[\"fragOffset\",13],[\"ttl\",8],[\"protocol\",8],[\"hdrChecksum\",16],[\"srcAddr\",32],[\"dstAddr\",32]]},{\"name\":\"routing_metadata_t\",\"id\":3,\"fields\":[[\"nhop_ipv4\",32]]}],\"headers\":[{\"name\":\"standard_metadata\",\"id\":0,\"header_type\":\"standard_metadata_t\"},{\"name\":\"ethernet\",\"id\":1,\"header_type\":\"ethernet_t\"},{\"name\":\"ipv4\",\"id\":2,\"header_type\":\"ipv4_t\"},{\"name\":\"routing_metadata\",\"id\":3,\"header_type\":\"routing_metadata_t\"}],\"header_stacks\":[],\"parsers\":[{\"name\":\"parser\",\"id\":0,\"init_state\":\"start\",\"parse_states\":[{\"name\":\"start\",\"id\":0,\"parser_ops\":[],\"transition_key\":[],\"transitions\":[{\"value\":\"default\",\"mask\":null,\"next_state\":\"parse_ethernet\"}]},{\"name\":\"parse_ethernet\",\"id\":1,\"parser_ops\":[{\"op\":\"extract\",\"parameters\":[{\"type\":\"regular\",\"value\":\"ethernet\"}]}],\"transition_key\":[{\"type\":\"field\",\"value\":[\"ethernet\",\"etherType\"]}],\"transitions\":[{\"value\":\"0x800\",\"mask\":null,\"next_state\":\"parse_ipv4\"},{\"value\":\"default\",\"mask\":null,\"next_state\":null}]},{\"name\":\"parse_ipv4\",\"id\":2,\"parser_ops\":[{\"op\":\"extract\",\"parameters\":[{\"type\":\"regular\",\"value\":\"ipv4\"}]}],\"transition_key\":[],\"transitions\":[{\"value\":\"default\",\"mask\":null,\"next_state\":null}]}]}],\"deparsers\":[{\"name\":\"deparser\",\"id\":0,\"order\":[\"ethernet\",\"ipv4\"]}],\"meter_arrays\":[],\"actions\":[{\"name\":\"set_nhop\",\"id\":0,\"runtime_data\":[{\"name\":\"nhop_ipv4\",\"bitwidth\":32},{\"name\":\"port\",\"bitwidth\":9}],\"primitives\":[{\"op\":\"modify_field\",\"parameters\":[{\"type\":\"field\",\"value\":[\"routing_metadata\",\"nhop_ipv4\"]},{\"type\":\"runtime_data\",\"value\":0}]},{\"op\":\"modify_field\",\"parameters\":[{\"type\":\"field\",\"value\":[\"standard_metadata\",\"egress_port\"]},{\"type\":\"runtime_data\",\"value\":1}]},{\"op\":\"add_to_field\",\"parameters\":[{\"type\":\"field\",\"value\":[\"ipv4\",\"ttl\"]},{\"type\":\"hexstr\",\"value\":\"-0x1\"}]}]},{\"name\":\"rewrite_mac\",\"id\":1,\"runtime_data\":[{\"name\":\"smac\",\"bitwidth\":48}],\"primitives\":[{\"op\":\"modify_field\",\"parameters\":[{\"type\":\"field\",\"value\":[\"ethernet\",\"srcAddr\"]},{\"type\":\"runtime_data\",\"value\":0}]}]},{\"name\":\"_drop\",\"id\":2,\"runtime_data\":[],\"primitives\":[{\"op\":\"drop\",\"parameters\":[]}]},{\"name\":\"set_dmac\",\"id\":3,\"runtime_data\":[{\"name\":\"dmac\",\"bitwidth\":48}],\"primitives\":[{\"op\":\"modify_field\",\"parameters\":[{\"type\":\"field\",\"value\":[\"ethernet\",\"dstAddr\"]},{\"type\":\"runtime_data\",\"value\":0}]}]}],\"pipelines\":[{\"name\":\"ingress\",\"id\":0,\"init_table\":\"_condition_0\",\"tables\":[{\"name\":\"ipv4_lpm\",\"id\":0,\"match_type\":\"lpm\",\"type\":\"simple\",\"max_size\":1024,\"with_counters\":false,\"key\":[{\"match_type\":\"lpm\",\"target\":[\"ipv4\",\"dstAddr\"]}],\"actions\":[\"set_nhop\",\"_drop\"],\"next_tables\":{\"set_nhop\":\"forward\",\"_drop\":\"forward\"},\"default_action\":null},{\"name\":\"forward\",\"id\":1,\"match_type\":\"exact\",\"type\":\"simple\",\"max_size\":512,\"with_counters\":false,\"key\":[{\"match_type\":\"exact\",\"target\":[\"routing_metadata\",\"nhop_ipv4\"]}],\"actions\":[\"set_dmac\",\"_drop\"],\"next_tables\":{\"set_dmac\":null,\"_drop\":null},\"default_action\":null}],\"conditionals\":[{\"name\":\"_condition_0\",\"id\":0,\"expression\":{\"type\":\"expression\",\"value\":{\"op\":\"and\",\"left\":{\"type\":\"expression\",\"value\":{\"op\":\"valid\",\"left\":null,\"right\":{\"type\":\"header\",\"value\":\"ipv4\"}}},\"right\":{\"type\":\"expression\",\"value\":{\"op\":\">\",\"left\":{\"type\":\"field\",\"value\":[\"ipv4\",\"ttl\"]},\"right\":{\"type\":\"hexstr\",\"value\":\"0x0\"}}}}},\"true_next\":\"ipv4_lpm\",\"false_next\":null}]},{\"name\":\"egress\",\"id\":1,\"init_table\":\"send_frame\",\"tables\":[{\"name\":\"send_frame\",\"id\":2,\"match_type\":\"exact\",\"type\":\"simple\",\"max_size\":256,\"with_counters\":false,\"key\":[{\"match_type\":\"exact\",\"target\":[\"standard_metadata\",\"egress_port\"]}],\"actions\":[\"rewrite_mac\",\"_drop\"],\"next_tables\":{\"rewrite_mac\":null,\"_drop\":null},\"default_action\":null}],\"conditionals\":[]}],\"calculations\":[{\"name\":\"ipv4_checksum\",\"id\":0,\"input\":[{\"type\":\"field\",\"value\":[\"ipv4\",\"version\"]},{\"type\":\"field\",\"value\":[\"ipv4\",\"ihl\"]},{\"type\":\"field\",\"value\":[\"ipv4\",\"diffserv\"]},{\"type\":\"field\",\"value\":[\"ipv4\",\"totalLen\"]},{\"type\":\"field\",\"value\":[\"ipv4\",\"identification\"]},{\"type\":\"field\",\"value\":[\"ipv4\",\"flags\"]},{\"type\":\"field\",\"value\":[\"ipv4\",\"fragOffset\"]},{\"type\":\"field\",\"value\":[\"ipv4\",\"ttl\"]},{\"type\":\"field\",\"value\":[\"ipv4\",\"protocol\"]},{\"type\":\"field\",\"value\":[\"ipv4\",\"srcAddr\"]},{\"type\":\"field\",\"value\":[\"ipv4\",\"dstAddr\"]}],\"algo\":\"csum16\"}],\"checksums\":[{\"name\":\"ipv4.hdrChecksum\",\"id\":0,\"target\":[\"ipv4\",\"hdrChecksum\"],\"type\":\"ipv4\"}],\"learn_lists\":[]}";

// NOLINTNEXTLINE(whitespace/line_length)
const std::string JSON_TEST_STRING_2 = "{\"header_types\":[{\"name\":\"standard_metadata_t\",\"id\":0,\"fields\":[[\"ingress_port\",9],[\"packet_length\",32],[\"egress_spec\",9],[\"egress_port\",9],[\"egress_instance\",32],[\"instance_type\",32],[\"clone_spec\",32],[\"_padding\",5]]},{\"name\":\"header_test_t\",\"id\":1,\"fields\":[[\"field8\",8],[\"field16\",16],[\"field20\",20],[\"field24\",24],[\"field32\",32],[\"field48\",48],[\"field64\",64],[\"_padding\",4]]}],\"headers\":[{\"name\":\"standard_metadata\",\"id\":0,\"header_type\":\"standard_metadata_t\"},{\"name\":\"header_test\",\"id\":1,\"header_type\":\"header_test_t\"},{\"name\":\"header_test_1\",\"id\":2,\"header_type\":\"header_test_t\"}],\"header_stacks\":[],\"parsers\":[{\"name\":\"parser\",\"id\":0,\"init_state\":\"start\",\"parse_states\":[{\"name\":\"start\",\"id\":0,\"parser_ops\":[],\"transition_key\":[],\"transitions\":[{\"value\":\"default\",\"mask\":null,\"next_state\":null}]}]}],\"deparsers\":[{\"name\":\"deparser\",\"id\":0,\"order\":[]}],\"meter_arrays\":[],\"actions\":[{\"name\":\"actionB\",\"id\":0,\"runtime_data\":[{\"name\":\"param\",\"bitwidth\":8}],\"primitives\":[{\"op\":\"modify_field\",\"parameters\":[{\"type\":\"field\",\"value\":[\"header_test\",\"field8\"]},{\"type\":\"runtime_data\",\"value\":0}]}]},{\"name\":\"actionA\",\"id\":1,\"runtime_data\":[{\"name\":\"param\",\"bitwidth\":48}],\"primitives\":[{\"op\":\"modify_field\",\"parameters\":[{\"type\":\"field\",\"value\":[\"header_test\",\"field48\"]},{\"type\":\"runtime_data\",\"value\":0}]}]},{\"name\":\"ActionLearn\",\"id\":2,\"runtime_data\":[],\"primitives\":[{\"op\":\"generate_digest\",\"parameters\":[{\"type\":\"hexstr\",\"value\":\"0x1\"},{\"type\":\"hexstr\",\"value\":\"0x1\"}]}]}],\"pipelines\":[{\"name\":\"ingress\",\"id\":0,\"init_table\":\"ExactOne\",\"tables\":[{\"name\":\"ExactOne\",\"id\":0,\"match_type\":\"exact\",\"type\":\"simple\",\"max_size\":512,\"with_counters\":true,\"key\":[{\"match_type\":\"exact\",\"target\":[\"header_test\",\"field32\"]}],\"actions\":[\"actionA\",\"actionB\"],\"next_tables\":{\"actionA\":\"LpmOne\",\"actionB\":\"LpmOne\"},\"default_action\":null},{\"name\":\"LpmOne\",\"id\":1,\"match_type\":\"lpm\",\"type\":\"simple\",\"max_size\":512,\"with_counters\":false,\"key\":[{\"match_type\":\"lpm\",\"target\":[\"header_test\",\"field32\"]}],\"actions\":[\"actionA\"],\"next_tables\":{\"actionA\":\"TernaryOne\"},\"default_action\":null},{\"name\":\"TernaryOne\",\"id\":2,\"match_type\":\"ternary\",\"type\":\"simple\",\"max_size\":512,\"with_counters\":false,\"key\":[{\"match_type\":\"ternary\",\"target\":[\"header_test\",\"field32\"]}],\"actions\":[\"actionA\"],\"next_tables\":{\"actionA\":\"ExactOneNA\"},\"default_action\":null},{\"name\":\"ExactOneNA\",\"id\":3,\"match_type\":\"exact\",\"type\":\"simple\",\"max_size\":512,\"with_counters\":false,\"key\":[{\"match_type\":\"exact\",\"target\":[\"header_test\",\"field20\"]}],\"actions\":[\"actionA\"],\"next_tables\":{\"actionA\":\"ExactTwo\"},\"default_action\":null},{\"name\":\"ExactTwo\",\"id\":4,\"match_type\":\"exact\",\"type\":\"simple\",\"max_size\":512,\"with_counters\":false,\"key\":[{\"match_type\":\"exact\",\"target\":[\"header_test\",\"field32\"]},{\"match_type\":\"exact\",\"target\":[\"header_test\",\"field16\"]}],\"actions\":[\"actionA\"],\"next_tables\":{\"actionA\":\"ExactAndValid\"},\"default_action\":null},{\"name\":\"ExactAndValid\",\"id\":5,\"match_type\":\"exact\",\"type\":\"simple\",\"max_size\":512,\"with_counters\":false,\"key\":[{\"match_type\":\"exact\",\"target\":[\"header_test\",\"field32\"]},{\"match_type\":\"valid\",\"target\":\"header_test_1\"}],\"actions\":[\"actionA\"],\"next_tables\":{\"actionA\":\"Learn\"},\"default_action\":null},{\"name\":\"Indirect\",\"id\":6,\"match_type\":\"exact\",\"type\":\"indirect\",\"act_prof_name\":\"ActProf\",\"max_size\":512,\"with_counters\":false,\"key\":[{\"match_type\":\"exact\",\"target\":[\"header_test\",\"field32\"]}],\"actions\":[\"actionA\",\"actionB\"],\"next_tables\":{\"actionA\":\"IndirectWS\",\"actionB\":\"IndirectWS\"},\"default_action\":null},{\"name\":\"IndirectWS\",\"id\":7,\"match_type\":\"exact\",\"type\":\"indirect_ws\",\"act_prof_name\":\"ActProfWS\",\"selector\":{\"algo\":\"crc16\",\"input\":[{\"type\":\"field\",\"value\":[\"header_test\",\"field24\"]},{\"type\":\"field\",\"value\":[\"header_test\",\"field48\"]},{\"type\":\"field\",\"value\":[\"header_test\",\"field64\"]}]},\"max_size\":512,\"with_counters\":false,\"key\":[{\"match_type\":\"exact\",\"target\":[\"header_test\",\"field32\"]}],\"actions\":[\"actionA\",\"actionB\"],\"next_tables\":{\"actionA\":null,\"actionB\":null},\"default_action\":null},{\"name\":\"Learn\",\"id\":8,\"match_type\":\"exact\",\"type\":\"simple\",\"max_size\":512,\"with_counters\":false,\"key\":[{\"match_type\":\"exact\",\"target\":[\"header_test\",\"field32\"]}],\"actions\":[\"ActionLearn\"],\"next_tables\":{\"ActionLearn\":\"Indirect\"},\"default_action\":null}],\"conditionals\":[]},{\"name\":\"egress\",\"id\":1,\"init_table\":null,\"tables\":[],\"conditionals\":[]}],\"calculations\":[{\"name\":\"SelectorHash\",\"id\":0,\"input\":[{\"type\":\"field\",\"value\":[\"header_test\",\"field24\"]},{\"type\":\"field\",\"value\":[\"header_test\",\"field48\"]},{\"type\":\"field\",\"value\":[\"header_test\",\"field64\"]}],\"algo\":\"crc16\"}],\"checksums\":[],\"learn_lists\":[{\"id\":1,\"name\":\"LearnDigest\",\"elements\":[{\"type\":\"field\",\"value\":[\"header_test\",\"field32\"]},{\"type\":\"field\",\"value\":[\"header_test\",\"field16\"]}]}]}";

TEST(P4Objects, LoadFromJSON1) {
  std::istringstream is(JSON_TEST_STRING_1);
  P4Objects objects;
  LookupStructureFactory factory;
  ASSERT_EQ(0, objects.init_objects(&is, &factory));

  ASSERT_NE(nullptr, objects.get_pipeline("ingress"));
  ASSERT_ANY_THROW(objects.get_pipeline("bad_pipeline"));
  ASSERT_EQ(nullptr, objects.get_pipeline_rt("bad_pipeline"));

  ASSERT_NE(nullptr, objects.get_action("ipv4_lpm", "_drop"));

  ASSERT_NE(nullptr, objects.get_parser("parser"));
  ASSERT_ANY_THROW(objects.get_parser("bad_parser"));
  ASSERT_EQ(nullptr, objects.get_parser_rt("bad_parser"));

  ASSERT_NE(nullptr, objects.get_deparser("deparser"));
  ASSERT_ANY_THROW(objects.get_deparser("bad_deparser"));
  ASSERT_EQ(nullptr, objects.get_deparser_rt("bad_deparser"));

  MatchTableAbstract *table;
  table = objects.get_abstract_match_table("forward");
  ASSERT_NE(nullptr, table);
  ASSERT_NE(nullptr, dynamic_cast<MatchTable *>(table));
  table = objects.get_abstract_match_table("ipv4_lpm");
  ASSERT_NE(nullptr, table);
  ASSERT_NE(nullptr, dynamic_cast<MatchTable *>(table));
  ASSERT_NE(nullptr, objects.get_match_action_table("forward"));
  ASSERT_NE(nullptr, objects.get_conditional("_condition_0"));
  ASSERT_NE(nullptr, objects.get_control_node("forward"));

  // objects.destroy_objects();
}

TEST(P4Objects, LoadFromJSON2) {
  std::istringstream is(JSON_TEST_STRING_2);
  P4Objects objects;
  LookupStructureFactory factory;
  ASSERT_EQ(0, objects.init_objects(&is, &factory));

  // this second test just checks that learn lists and indirect tables get
  // parsed correctly

  MatchTableAbstract *table;
  table = objects.get_abstract_match_table("Indirect");
  ASSERT_NE(nullptr, table);
  ASSERT_NE(nullptr, dynamic_cast<MatchTableIndirect *>(table));
  table = objects.get_abstract_match_table("IndirectWS");
  ASSERT_NE(nullptr, table);
  ASSERT_NE(nullptr, dynamic_cast<MatchTableIndirectWS *>(table));
}

TEST(P4Objects, Empty) {
  std::istringstream is("{}");
  P4Objects objects;
  LookupStructureFactory factory;
  ASSERT_EQ(0, objects.init_objects(&is, &factory));
}

TEST(P4Objects, UnknownPrimitive) {
  // NOLINTNEXTLINE(whitespace/line_length)
  std::istringstream is("{\"actions\":[{\"name\":\"_drop\",\"id\":2,\"runtime_data\":[],\"primitives\":[{\"op\":\"bad_primitive\",\"parameters\":[]}]}]}");
  std::stringstream os;
  P4Objects objects(os);
  LookupStructureFactory factory;
  std::string expected("Unknown primitive action: bad_primitive\n");
  ASSERT_NE(0, objects.init_objects(&is, &factory));
  EXPECT_EQ(expected, os.str());
}

TEST(P4Objects, PrimitiveBadParamCount) {
  // NOLINTNEXTLINE(whitespace/line_length)
  std::istringstream is("{\"actions\":[{\"name\":\"_drop\",\"id\":2,\"runtime_data\":[],\"primitives\":[{\"op\":\"drop\",\"parameters\":[{\"type\":\"hexstr\",\"value\":\"0xab\"}]}]}]}");
  std::stringstream os;
  LookupStructureFactory factory;
  P4Objects objects(os);
  std::string expected(
      "Invalid number of parameters for primitive action drop: "
      "expected 0 but got 1\n");
  ASSERT_NE(0, objects.init_objects(&is, &factory));
  EXPECT_EQ(expected, os.str());
}

TEST(P4Objects, UnknownHash) {
  // NOLINTNEXTLINE(whitespace/line_length)
  std::istringstream is("{\"calculations\":[{\"name\":\"calc\",\"id\":0,\"input\":[],\"algo\":\"bad_hash_1\"}]}");
  std::stringstream os;
  LookupStructureFactory factory;
  P4Objects objects(os);
  std::string expected("Unknown hash algorithm: bad_hash_1\n");
  ASSERT_NE(0, objects.init_objects(&is, &factory));
  EXPECT_EQ(expected, os.str());
}

TEST(P4Objects, UnknownHashSelector) {
  // NOLINTNEXTLINE(whitespace/line_length)
  std::istringstream is("{\"pipelines\":[{\"name\":\"ingress\",\"id\":0,\"init_table\":\"t1\",\"tables\":[{\"name\":\"t1\",\"id\":0,\"match_type\":\"exact\",\"type\":\"indirect_ws\",\"act_prof_name\":\"ap1\",\"selector\":{\"algo\":\"bad_hash_2\",\"input\":[]},\"max_size\":1024,\"with_counters\":false,\"key\":[],\"actions\":[\"_drop\"],\"next_tables\":{\"_drop\":null},\"default_action\":null}]}]}");
  std::stringstream os;
  LookupStructureFactory factory;
  P4Objects objects(os);
  std::string expected("Unknown hash algorithm: bad_hash_2\n");
  ASSERT_NE(0, objects.init_objects(&is, &factory));
  EXPECT_EQ(expected, os.str());
}

TEST(P4Objects, RequiredField) {
  std::istringstream is("{}");
  std::set<P4Objects::header_field_pair> required_fields;
  required_fields.insert(std::make_pair("standard_metadata", "egress_port"));
  std::stringstream os;
  LookupStructureFactory factory;
  P4Objects objects(os);
  std::string expected(
      "Field standard_metadata.egress_port is required by switch target "
      "but is not defined\n");
  // 0 for device_id, 0 for cxt_id, nullptr for transport
  ASSERT_NE(0, objects.init_objects(&is, &factory, 0, 0, nullptr,
                                    required_fields));
  EXPECT_EQ(expected, os.str());
}

TEST(P4Objects, FieldAlias) {
  // NOLINTNEXTLINE(whitespace/line_length)
  std::istringstream is("{\"header_types\":[{\"name\":\"hdrA_t\",\"id\":0,\"fields\":[[\"f1\",8],[\"f2\",8]]}],\"headers\":[{\"name\":\"hdrA\",\"id\":0,\"header_type\":\"hdrA_t\"}],\"field_aliases\":[[\"this_is.my_alias\",[\"hdrA\",\"f1\"]]]}");
  P4Objects objects;
  LookupStructureFactory factory;
  ASSERT_EQ(0, objects.init_objects(&is, &factory));

  ASSERT_TRUE(objects.field_exists("hdrA", "f1"));
  ASSERT_TRUE(objects.field_exists("this_is", "my_alias"));

  ASSERT_FALSE(objects.field_exists("hdrA", "fbad"));
  ASSERT_FALSE(objects.field_exists("hdrBad", "f1"));
  ASSERT_FALSE(objects.field_exists("this_is_not", "my_alias"));
  ASSERT_FALSE(objects.field_exists("this_is", "not_my_alias"));
}

TEST(P4Objects, Reset) {
  std::istringstream is(JSON_TEST_STRING_1);
  P4Objects objects;
  LookupStructureFactory factory;
  ASSERT_EQ(0, objects.init_objects(&is, &factory));
  // TODO(antonin): this test is not doing anything useful, but it is pretty
  // hard to test for reset
  objects.reset_state();
}

class my_extern_type : public ExternType {
 public:
  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(attr1);
  }

  void methodA() { }

  void init() override { }

 private:
  Data attr1{0};
};

BM_REGISTER_EXTERN(my_extern_type);
BM_REGISTER_EXTERN_METHOD(my_extern_type, methodA);

namespace {

void create_extern_instance_json(std::ostream *ss,
                                 const std::string &instance_name,
                                 const std::string &type_name,
                                 const std::string &attr_name,
                                 const std::string &attr_type) {
  *ss << "{\"extern_instances\":[{\"name\":\""
      << instance_name
      << "\",\"id\":22,\"type\":\""
      << type_name
      << "\",\"attribute_values\":[{\"name\":\""
      << attr_name
      << "\",\"type\":\""
      << attr_type
      << "\",\"value\":\"0xab\"}]}]}";
}

}  // namespace

TEST(P4Objects, ExternInstanceDeclaration) {
  std::stringstream is;

  {
    std::stringstream os;
    P4Objects objects(os);
    LookupStructureFactory factory;
    create_extern_instance_json(&is, "my_extern_instance", "my_extern_type",
                                "attr1", "hexstr");
    ASSERT_EQ(0, objects.init_objects(&is, &factory));
  }

  {
    std::stringstream os;
    P4Objects objects(os);
    LookupStructureFactory factory;
    create_extern_instance_json(&is, "my_extern_instance", "bad_type",
                                "attr1", "hexstr");
    std::string expected_error_msg(
        "Invalid reference to extern type 'bad_type'\n");
    ASSERT_NE(0, objects.init_objects(&is, &factory));
    EXPECT_EQ(expected_error_msg, os.str());
  }

  {
    std::stringstream os;
    P4Objects objects(os);
    LookupStructureFactory factory;
    create_extern_instance_json(&is, "my_extern_instance", "my_extern_type",
                                "bad_attr", "hexstr");
    std::string expected_error_msg(
        "Extern type 'my_extern_type' has no attribute 'bad_attr'\n");
    ASSERT_NE(0, objects.init_objects(&is, &factory));
    EXPECT_EQ(expected_error_msg, os.str());
  }

  {
    std::stringstream os;
    P4Objects objects(os);
    LookupStructureFactory factory;
    create_extern_instance_json(&is, "my_extern_instance", "my_extern_type",
                                "attr1", "unsupported_type");
    std::string expected_error_msg(
        "Only attributes of type 'hexstr', 'string' or 'expression' are "
        "supported for extern instance attribute initialization\n");
    ASSERT_NE(0, objects.init_objects(&is, &factory));
    EXPECT_EQ(expected_error_msg, os.str());
  }
}

TEST(P4Objects, TableDefaultEntry) {
  std::stringstream is;
  is << "{\"pipelines\":[{\"name\":\"ingress\",\"id\":0,\"init_table\":\"t0\","
     << "\"tables\":[{\"name\":\"t0\",\"id\":0,\"match_type\":\"exact\","
     << "\"type\":\"simple\",\"max_size\":1,\"with_counters\":false,"
     << "\"key\":[],\"action_ids\":[0],\"next_tables\":{\"a0\":null},"
     << "\"default_entry\":{\"action_id\":0,\"action_const\":true,"
     << "\"action_data\":[\"0xab\"],\"action_entry_const\":true}}]}],"
     << "\"actions\":[{\"name\":\"a0\",\"id\":0,\"runtime_data\":"
     << "[{\"name\":\"p\",\"bitwidth\":32}],\"primitives\":[]}]}";
  P4Objects objects;
  LookupStructureFactory factory;
  ASSERT_EQ(0, objects.init_objects(&is, &factory));
  auto t_ = objects.get_abstract_match_table("t0");
  auto t = dynamic_cast<MatchTable *>(t_);
  ASSERT_NE(nullptr, t);
  MatchTable::Entry entry;
  auto rc = t->get_default_entry(&entry);
  ASSERT_EQ(MatchErrorCode::SUCCESS, rc);
  ASSERT_EQ("a0", entry.action_fn->get_name());
  ASSERT_EQ(1u, entry.action_data.size());
  ASSERT_EQ(0xab, entry.action_data.get(0).get_int());
}

TEST(P4Objects, ParseVset) {
  fs::path json_path = fs::path(TESTDATADIR) / fs::path("parse_vset.json");
  std::ifstream is(json_path.string());
  P4Objects objects;
  LookupStructureFactory factory;
  ASSERT_EQ(0, objects.init_objects(&is, &factory));
  auto parse_vset_1 = objects.get_parse_vset("pv1");
  ASSERT_NE(nullptr, parse_vset_1);
  auto parse_vset_2 = objects.get_parse_vset("pv2");
  ASSERT_NE(nullptr, parse_vset_2);
  ASSERT_EQ("pv1", parse_vset_1->get_name());
  ASSERT_EQ(16, parse_vset_1->get_compressed_bitwidth());
}

extern bool WITH_VALGRIND;  // defined in main.cpp

TEST(P4Objects, HeaderStackArith) {
  std::unique_ptr<PHV> phv;

  // gtest complains when a deathtest has multiple threads running
  // by adding a nested scope here, I ensure that the threads started by
  // P4Objects are destroyed before ASSERT_DEATH
  {
    fs::path json_path = fs::path(TESTDATADIR) / fs::path("header_stack.json");
    std::ifstream is(json_path.string());
    P4Objects objects;
    LookupStructureFactory factory;
    ASSERT_EQ(0, objects.init_objects(&is, &factory));
    const auto &phv_factory = objects.get_phv_factory();
    phv = phv_factory.create();
  }

  // check that arith has been enabled on hdr[x].f1 (but not on hdr[x].f2)
  const auto &h0_f1 = phv->get_field("hdr[0].f1");
  const auto &h1_f1 = phv->get_field("hdr[1].f1");
  const auto &h0_f2 = phv->get_field("hdr[0].f2");
  const auto &h1_f2 = phv->get_field("hdr[1].f2");
  ASSERT_NO_THROW(h1_f1.get_int());
  ASSERT_NO_THROW(h0_f1.get_int());

  if (!WITH_VALGRIND) {
    ASSERT_DEATH(h0_f2.get_int(), "Assertion .*failed");
    ASSERT_DEATH(h1_f2.get_int(), "Assertion .*failed");
  }
}

TEST(P4Objects, Errors) {
  std::istringstream is(
      "{\"errors\":[[\"NoError\",0],[\"PacketTooShort\",1]]}");
  P4Objects objects;
  LookupStructureFactory factory;
  ASSERT_EQ(0, objects.init_objects(&is, &factory));
  auto error_codes = objects.get_error_codes();
  ASSERT_TRUE(error_codes.exists("NoError"));
  ASSERT_TRUE(error_codes.exists("PacketTooShort"));
  ASSERT_FALSE(error_codes.exists("InvalidError"));
}

TEST(P4Objects, InvalidErrors) {
  std::string expected_error_msg("Invalid errors specification in json\n");

  {
    // duplicate name
    std::istringstream is("{\"errors\":[[\"error0\",0],[\"error0\",1]]}");
    std::stringstream os;
    P4Objects objects(os);
    LookupStructureFactory factory;
    ASSERT_NE(0, objects.init_objects(&is, &factory));
    EXPECT_EQ(expected_error_msg, os.str());
  }

  {
    // duplicate value
    std::istringstream is("{\"errors\":[[\"error0\",0],[\"error1\",0]]}");
    std::stringstream os;
    P4Objects objects(os);
    LookupStructureFactory factory;
    ASSERT_NE(0, objects.init_objects(&is, &factory));
    EXPECT_EQ(expected_error_msg, os.str());
  }
}

TEST(P4Objects, ParserVerify) {
  auto create_json = [](int error_v, std::ostream *ss) {
    *ss << "{\"errors\":[[\"NoError\",0]],"
        << "\"parsers\":[{\"name\":\"parser\",\"id\":0,\"init_state\":"
        << "\"start\",\"parse_states\":[{\"name\":\"start\",\"id\":0,"
        << "\"parser_ops\":[{\"op\":\"verify\",\"parameters\":[null,"
        << error_v << "]}],\"transition_key\":[],\"transitions\":[]}]}]}";
  };

  {
    std::stringstream is;
    create_json(0, &is);
    P4Objects objects;
    LookupStructureFactory factory;
    ASSERT_EQ(0, objects.init_objects(&is, &factory));
  }

  {
    std::stringstream is;
    create_json(1000, &is);
    std::stringstream os;
    P4Objects objects(os);
    LookupStructureFactory factory;
    ASSERT_NE(0, objects.init_objects(&is, &factory));
    std::string expected_error_msg("Invalid error code in verify statement\n");
    EXPECT_EQ(expected_error_msg, os.str());
  }
}

TEST(P4Objects, ActionParamString) {
  std::stringstream is(
      "{\"actions\":[{\"name\":\"a0\",\"id\":0,\"runtime_data\":[],"
      "\"primitives\":[{\"op\":\"ignore_string\","
      "\"parameters\":[{\"type\":\"string\",\"value\":\"testString\"}]}]}]}");
  P4Objects objects;
  LookupStructureFactory factory;
  ASSERT_EQ(0, objects.init_objects(&is, &factory));
}

// convenience classes to generate some test JSON input; as of now this is
// pretty limited but we could extend it if this proves useful
namespace {

class JsonExpr {
 public:
  static JsonExpr load_header(const std::string &name) {
    JsonExpr res;
    res.json["type"] = "header";
    res.json["value"] = name;
    return res;
  }

  static JsonExpr load_bool(bool v) {
    JsonExpr res;
    res.json["type"] = "bool";
    res.json["value"] = v;
    return res;
  }

  static JsonExpr expression(const std::string &op, const JsonExpr &left,
                             const JsonExpr &right) {
    JsonExpr res;
    res.json["type"] = "expression";
    res.json["op"] = op;
    res.json["left"] = left.json;
    res.json["right"] = right.json;
    return res;
  }

  const Json::Value &get_json() const { return json; }

 private:
  JsonExpr() { }

  Json::Value json;
};

class JsonBuilder {
 public:
  JsonBuilder() {
    json["header_types"] = Json::Value(Json::arrayValue);
    json["headers"] = Json::Value(Json::arrayValue);
    json["pipelines"] = Json::Value(Json::arrayValue);
  }

  void add_header_type(const std::string &name) {
    auto &header_types = json["header_types"];
    Json::Value header_type(Json::objectValue);
    header_type["name"] = name;
    header_type["id"] = header_types.size();
    header_type["fields"] = Json::Value(Json::arrayValue);
    Json::Value field(Json::arrayValue);
    field.append("f8");
    field.append(8);
    header_type["fields"].append(field);
    header_types.append(header_type);
  }

  void add_header(const std::string &name,
                  const std::string &header_type_name) {
    auto &headers = json["headers"];
    Json::Value header(Json::objectValue);
    header["name"] = name;
    header["id"] = headers.size();
    header["header_type"] = header_type_name;
    header["metadata"] = false;
    headers.append(header);
  }

  // only supports one condition for now
  void add_condition(const std::string &name, const JsonExpr &expr) {
    auto &pipelines = json["pipelines"];
    Json::Value pipeline(Json::objectValue);
    pipeline["name"] = "pipe";
    pipeline["id"] = 0;
    pipeline["init_table"] = name;
    pipeline["tables"] = Json::Value(Json::arrayValue);
    pipeline["conditionals"] = Json::Value(Json::arrayValue);
    Json::Value cond(Json::objectValue);
    cond["name"] = name;
    cond["id"] = 0;
    Json::Value expression(Json::objectValue);
    expression["type"] = "expression";
    expression["value"] = expr.get_json();
    cond["expression"] = expression;
    cond["true_next"] = Json::Value();  // null
    cond["false_next"] = Json::Value();  // null
    pipeline["conditionals"].append(cond);
    pipelines.append(pipeline);
  }

  std::string to_string() const {
    Json::StyledWriter writer;
    return writer.write(json);
  }

 private:
  Json::Value json;
};

}  // namespace

class P4ObjectsExprBuilderTest : public ::testing::Test {
 protected:
  P4Objects objects;
  LookupStructureFactory factory;

  P4ObjectsExprBuilderTest() { }
};

TEST_F(P4ObjectsExprBuilderTest, EqHeader) {
  JsonBuilder builder;
  builder.add_header_type("hdr_t");
  builder.add_header("hdr1", "hdr_t");
  builder.add_header("hdr2", "hdr_t");
  auto e1 = JsonExpr::load_header("hdr1");
  auto e2 = JsonExpr::load_header("hdr2");
  auto expr = JsonExpr::expression("==", e1, e2);
  builder.add_condition("c0", expr);
  std::stringstream is(builder.to_string());
  ASSERT_EQ(0, objects.init_objects(&is, &factory));
  const auto cond = objects.get_conditional("c0");
  const auto &phv_factory = objects.get_phv_factory();
  auto phv = phv_factory.create();
  auto &hdr1 = phv->get_header("hdr1");
  auto &hdr2 = phv->get_header("hdr2");
  ASSERT_FALSE(cond->eval(*phv));
  hdr1.mark_valid(); hdr2.mark_valid();
  ASSERT_TRUE(cond->eval(*phv));
}

TEST_F(P4ObjectsExprBuilderTest, EqBool) {
  JsonBuilder builder;
  auto e1 = JsonExpr::load_bool(true);
  auto e2 = JsonExpr::load_bool(true);
  auto expr = JsonExpr::expression("!=", e1, e2);
  builder.add_condition("c0", expr);
  std::stringstream is(builder.to_string());
  ASSERT_EQ(0, objects.init_objects(&is, &factory));
  const auto cond = objects.get_conditional("c0");
  const auto &phv_factory = objects.get_phv_factory();
  auto phv = phv_factory.create();
  ASSERT_FALSE(cond->eval(*phv));
}
