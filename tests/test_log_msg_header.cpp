/* Copyright 2019 RT-RK Computer Based System
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

#include <gtest/gtest.h>

#include <bm/bm_sim/actions.h>
#include <bm/bm_sim/core/primitives.h>
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/phv.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/P4Objects.h>

#include <vector>
#include <string>
#include <fstream>
#include <sstream>

#include <boost/filesystem.hpp>

#include "jsoncpp/json.h"

using bm::PHVFactory;
using bm::ActionFn;
using bm::ActionFnEntry;
using bm::PHVSourceIface;
using bm::ActionPrimitive_;
using bm::ActionOpcodesMap;
using bm::Data;
using bm::Packet;
using bm::P4Objects;
using bm::LookupStructureFactory;

namespace fs = boost::filesystem;


using namespace bm;
class LogTest : public ::testing::Test {
 protected:
  PHVFactory phv_factory;
  std::unique_ptr<PHV> phv;

  P4Objects objects;


  HeaderType testHeaderType;
  header_id_t testHeader1{0}, testHeader2{1}, testHeader3{2};

  ActionFn testActionFn;
  ActionFnEntry testActionFnEntry;

  std::unique_ptr<PHVSourceIface> phv_source{nullptr};
  std::unique_ptr<Packet> pkt{nullptr};

  LogTest()
      : testHeaderType("test_t", 0),
        testActionFn("test_primitive", 0, 1),
        testActionFnEntry(&testActionFn),
        phv_source(PHVSourceIface::make_phv_source()) {
          testHeaderType.push_back_field("f16", 16);
          testHeaderType.push_back_field("f48", 48);
          phv_factory.push_back_header("test1", testHeader1, testHeaderType);
          phv_factory.push_back_header("test2", testHeader2, testHeaderType);
          phv_factory.push_back_header(
            "test3", testHeader3, testHeaderType, true);
        }

  virtual void SetUp() {
    phv_source->set_phv_factory(0, &phv_factory);
    pkt = std::unique_ptr<Packet>(new Packet(
        Packet::make_new(phv_source.get())));
    phv = phv_factory.create();
  }
};

namespace {

struct CheckLogs {
  CheckLogs() {
    bm::Logger::set_logger_ostream(ss);
  }

  ~CheckLogs() {
    bm::Logger::unset_logger();
  }

  bool contains(const char *expected) const {
    auto actual = str();
    auto found = actual.find(expected);
    return found != std::string::npos;
  }

  std::string str() const {
    return ss.str();
  }

  std::stringstream ss;
};

}  // namespace



TEST_F(LogTest, LogMessageInvalidHeader) {
  CheckLogs logs;
  std::unique_ptr<ActionPrimitive_> primitive;
  std::unique_ptr<ActionPrimitive_> primitive1;

  std::string primitive_name1("assign");
  primitive1 = ActionOpcodesMap::get_instance()->get_primitive("assign");
  ASSERT_NE(nullptr, primitive1);

  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader2, 0);
  testActionFn.parameter_push_back_const(Data(4));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader2, 1);
  testActionFn.parameter_push_back_const(Data(5));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader2, 2);
  testActionFn.parameter_push_back_const(Data(0));


  std::string primitive_name("log_msg");
  primitive = ActionOpcodesMap::get_instance()->get_primitive("log_msg");
  ASSERT_NE(nullptr, primitive);

  testActionFn.push_back_primitive(primitive.get());
  testActionFn.parameter_push_back_string("x = {}");
  testActionFn.parameter_start_vector();
  testActionFn.parameter_push_back_header(testHeader2);
  testActionFn.parameter_end_vector();

  testActionFnEntry(pkt.get());

  EXPECT_TRUE(logs.contains("x = {'$valid$': 0, 'f16': 4, 'f48': 5}"));
}


TEST_F(LogTest, LogMessageDataInvalidHeader) {
  CheckLogs logs;
  std::unique_ptr<ActionPrimitive_> primitive;
  std::unique_ptr<ActionPrimitive_> primitive1;

  std::string primitive_name1("assign");
  primitive1 = ActionOpcodesMap::get_instance()->get_primitive("assign");
  ASSERT_NE(nullptr, primitive1);

  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 0);
  testActionFn.parameter_push_back_const(Data(3));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 1);
  testActionFn.parameter_push_back_const(Data(5));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 2);
  testActionFn.parameter_push_back_const(Data(0));


  std::string primitive_name("log_msg");
  primitive = ActionOpcodesMap::get_instance()->get_primitive("log_msg");
  ASSERT_NE(nullptr, primitive);

  testActionFn.push_back_primitive(primitive.get());
  testActionFn.parameter_push_back_string("x1 = {}, x2 = {}");
  testActionFn.parameter_start_vector();
  testActionFn.parameter_push_back_const(Data("0x04"));
  testActionFn.parameter_push_back_header(testHeader1);
  testActionFn.parameter_end_vector();

  testActionFnEntry(pkt.get());

  EXPECT_TRUE(logs.contains("x1 = 4, x2 = {'$valid$': 0, 'f16': 3, 'f48': 5}"));
}


TEST_F(LogTest, LogMessageHeader) {
  CheckLogs logs;
  std::unique_ptr<ActionPrimitive_> primitive;
  std::unique_ptr<ActionPrimitive_> primitive1;

  std::string primitive_name1("assign");
  primitive1 = ActionOpcodesMap::get_instance()->get_primitive("assign");
  ASSERT_NE(nullptr, primitive1);

  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader2, 0);
  testActionFn.parameter_push_back_const(Data(2));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader2, 1);
  testActionFn.parameter_push_back_const(Data(9));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader2, 2);
  testActionFn.parameter_push_back_const(Data(1));


  std::string primitive_name("log_msg");
  primitive = ActionOpcodesMap::get_instance()->get_primitive("log_msg");
  ASSERT_NE(nullptr, primitive);

  testActionFn.push_back_primitive(primitive.get());
  testActionFn.parameter_push_back_string("x = {}");
  testActionFn.parameter_start_vector();
  testActionFn.parameter_push_back_header(testHeader2);
  testActionFn.parameter_end_vector();

  testActionFnEntry(pkt.get());

  EXPECT_TRUE(logs.contains("x = {'$valid$': 1, 'f16': 2, 'f48': 9}"));
}

TEST_F(LogTest, LogMessageDataHeader) {
  CheckLogs logs;
  std::unique_ptr<ActionPrimitive_> primitive;
  std::unique_ptr<ActionPrimitive_> primitive1;

  std::string primitive_name1("assign");
  primitive1 = ActionOpcodesMap::get_instance()->get_primitive("assign");
  ASSERT_NE(nullptr, primitive1);

  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader2, 0);
  testActionFn.parameter_push_back_const(Data(2));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader2, 1);
  testActionFn.parameter_push_back_const(Data(3));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader2, 2);
  testActionFn.parameter_push_back_const(Data(1));


  std::string primitive_name("log_msg");
  primitive = ActionOpcodesMap::get_instance()->get_primitive("log_msg");
  ASSERT_NE(nullptr, primitive);

  testActionFn.push_back_primitive(primitive.get());
  testActionFn.parameter_push_back_string("x1 = {}, x2 = {}");
  testActionFn.parameter_start_vector();
  testActionFn.parameter_push_back_const(Data(1));
  testActionFn.parameter_push_back_header(testHeader2);
  testActionFn.parameter_end_vector();

  testActionFnEntry(pkt.get());

  EXPECT_TRUE(logs.contains("x1 = 1, x2 = {'$valid$': 1, 'f16': 2, 'f48': 3}"));
}

TEST_F(LogTest, LogMessageTwoHeaders) {
  CheckLogs logs;
  std::unique_ptr<ActionPrimitive_> primitive;
  std::unique_ptr<ActionPrimitive_> primitive1;

  std::string primitive_name1("assign");
  primitive1 = ActionOpcodesMap::get_instance()->get_primitive("assign");
  ASSERT_NE(nullptr, primitive1);

  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 0);
  testActionFn.parameter_push_back_const(Data(4));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 1);
  testActionFn.parameter_push_back_const(Data(5));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 2);
  testActionFn.parameter_push_back_const(Data(1));

  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader2, 0);
  testActionFn.parameter_push_back_const(Data(2));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader2, 1);
  testActionFn.parameter_push_back_const(Data(3));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader2, 2);
  testActionFn.parameter_push_back_const(Data(1));


  std::string primitive_name("log_msg");
  primitive = ActionOpcodesMap::get_instance()->get_primitive("log_msg");
  ASSERT_NE(nullptr, primitive);

  testActionFn.push_back_primitive(primitive.get());
  testActionFn.parameter_push_back_string("x1 = {}, x2 = {}");
  testActionFn.parameter_start_vector();
  testActionFn.parameter_push_back_header(testHeader1);
  testActionFn.parameter_push_back_header(testHeader2);
  testActionFn.parameter_end_vector();

  testActionFnEntry(pkt.get());

  EXPECT_TRUE(logs.contains(
    "x1 = {'$valid$': 1, 'f16': 4, 'f48': 5}, "
    "x2 = {'$valid$': 1, 'f16': 2, 'f48': 3}"));
}

TEST_F(LogTest, LogMessageDataStruct) {
  CheckLogs logs;
  std::unique_ptr<ActionPrimitive_> primitive;
  std::unique_ptr<ActionPrimitive_> primitive1;

  std::string primitive_name1("assign");
  primitive1 = ActionOpcodesMap::get_instance()->get_primitive("assign");
  ASSERT_NE(nullptr, primitive1);

  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader3, 0);
  testActionFn.parameter_push_back_const(Data(4));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader3, 1);
  testActionFn.parameter_push_back_const(Data(9));


  std::string primitive_name("log_msg");
  primitive = ActionOpcodesMap::get_instance()->get_primitive("log_msg");
  ASSERT_NE(nullptr, primitive);


  testActionFn.push_back_primitive(primitive.get());
  testActionFn.parameter_push_back_string("x1 = {}, x2 = {}");
  testActionFn.parameter_start_vector();
  testActionFn.parameter_push_back_const(Data(1));
  testActionFn.parameter_push_back_header(testHeader3);
  testActionFn.parameter_end_vector();

  testActionFnEntry(pkt.get());

  EXPECT_TRUE(logs.contains("x1 = 1, x2 = {'f16': 4, 'f48': 9}"));
}

TEST_F(LogTest, LogMessageHeaderStruct) {
  CheckLogs logs;
  std::unique_ptr<ActionPrimitive_> primitive;
  std::unique_ptr<ActionPrimitive_> primitive1;

  std::string primitive_name1("assign");
  primitive1 = ActionOpcodesMap::get_instance()->get_primitive("assign");
  ASSERT_NE(nullptr, primitive1);

  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 0);
  testActionFn.parameter_push_back_const(Data(4));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 1);
  testActionFn.parameter_push_back_const(Data(5));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 2);
  testActionFn.parameter_push_back_const(Data(1));

  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader3, 0);
  testActionFn.parameter_push_back_const(Data(2));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader3, 1);
  testActionFn.parameter_push_back_const(Data(3));

  std::string primitive_name("log_msg");
  primitive = ActionOpcodesMap::get_instance()->get_primitive("log_msg");
  ASSERT_NE(nullptr, primitive);

  testActionFn.push_back_primitive(primitive.get());
  testActionFn.parameter_push_back_string("x1 = {}, x2 = {}");
  testActionFn.parameter_start_vector();
  testActionFn.parameter_push_back_header(testHeader1);
  testActionFn.parameter_push_back_header(testHeader3);
  testActionFn.parameter_end_vector();

  testActionFnEntry(pkt.get());

  EXPECT_TRUE(logs.contains(
    "x1 = {'$valid$': 1, 'f16': 4, 'f48': 5}, x2 = {'f16': 2, 'f48': 3}"));
}

TEST_F(LogTest, LogMessageStructWithHeader) {
  CheckLogs logs;
  std::unique_ptr<ActionPrimitive_> primitive;
  std::unique_ptr<ActionPrimitive_> primitive1;

  std::string primitive_name1("assign");
  primitive1 = ActionOpcodesMap::get_instance()->get_primitive("assign");
  ASSERT_NE(nullptr, primitive1);

  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 0);
  testActionFn.parameter_push_back_const(Data(1));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 1);
  testActionFn.parameter_push_back_const(Data(2));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 2);
  testActionFn.parameter_push_back_const(Data(1));


  std::string primitive_name("log_msg");
  primitive = ActionOpcodesMap::get_instance()->get_primitive("log_msg");
  ASSERT_NE(nullptr, primitive);

  std::vector<std::pair<int, Data>> vec_data{};
  std::vector<std::pair<int, header_id_t>> vec_header_id{};
  vec_data.push_back(std::make_pair(0, Data(3)));
  vec_data.push_back(std::make_pair(1, Data(5)));
  vec_header_id.push_back(std::make_pair(2, testHeader1));

  testActionFn.push_back_primitive(primitive.get());
  testActionFn.parameter_push_back_string("x = {}");
  testActionFn.parameter_start_vector();
  testActionFn.parameter_push_back_list(
        std::unique_ptr<List>(new List(vec_data, vec_header_id)));
  testActionFn.parameter_end_vector();

  testActionFnEntry(pkt.get());

  EXPECT_TRUE(logs.contains(
    "x = {3, 5, {'$valid$': 1, 'f16': 1, 'f48': 2}}"));
}

TEST_F(LogTest, LogMessageStructWithHeader2) {
  CheckLogs logs;
  std::unique_ptr<ActionPrimitive_> primitive;
  std::unique_ptr<ActionPrimitive_> primitive1;

  std::string primitive_name1("assign");
  primitive1 = ActionOpcodesMap::get_instance()->get_primitive("assign");
  ASSERT_NE(nullptr, primitive1);

  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader3, 0);
  testActionFn.parameter_push_back_const(Data(2));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader3, 1);
  testActionFn.parameter_push_back_const(Data(3));

  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 0);
  testActionFn.parameter_push_back_const(Data(4));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 1);
  testActionFn.parameter_push_back_const(Data(5));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 2);
  testActionFn.parameter_push_back_const(Data(1));


  std::string primitive_name("log_msg");
  primitive = ActionOpcodesMap::get_instance()->get_primitive("log_msg");
  ASSERT_NE(nullptr, primitive);

  std::vector<std::pair<int, Data>> vec_data{};
  std::vector<std::pair<int, header_id_t>> vec_header_id{};
  vec_data.push_back(std::make_pair(0, Data(3)));
  vec_header_id.push_back(std::make_pair(1, testHeader3));
  vec_data.push_back(std::make_pair(2, Data(4)));
  vec_header_id.push_back(std::make_pair(3, testHeader1));

  testActionFn.push_back_primitive(primitive.get());
  testActionFn.parameter_push_back_string("x = {}");
  testActionFn.parameter_start_vector();
  testActionFn.parameter_push_back_list(
        std::unique_ptr<List>(new List(vec_data, vec_header_id)));
  testActionFn.parameter_end_vector();

  testActionFnEntry(pkt.get());

  EXPECT_TRUE(logs.contains(
    "x = {3, {'f16': 2, 'f48': 3}, 4, {'$valid$': 1, 'f16': 4, 'f48': 5}}"));
}

TEST_F(LogTest, LogMessageStructWithHeader3) {
  CheckLogs logs;
  std::unique_ptr<ActionPrimitive_> primitive;
  std::unique_ptr<ActionPrimitive_> primitive1;


  std::string primitive_name1("assign");
  primitive1 = ActionOpcodesMap::get_instance()->get_primitive("assign");
  ASSERT_NE(nullptr, primitive1);

  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 0);
  testActionFn.parameter_push_back_const(Data(1));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 1);
  testActionFn.parameter_push_back_const(Data(2));
  testActionFn.push_back_primitive(primitive1.get());
  testActionFn.parameter_push_back_field(testHeader1, 2);
  testActionFn.parameter_push_back_const(Data(1));


  std::string primitive_name("log_msg");
  primitive = ActionOpcodesMap::get_instance()->get_primitive("log_msg");
  ASSERT_NE(nullptr, primitive);

  std::vector<std::pair<int, Data>> vec_data{};
  std::vector<std::pair<int, header_id_t>> vec_header_id{};
  vec_data.push_back(std::make_pair(0, Data(3)));
  vec_data.push_back(std::make_pair(2, Data(5)));
  vec_header_id.push_back(std::make_pair(1, testHeader1));

  testActionFn.push_back_primitive(primitive.get());
  testActionFn.parameter_push_back_string("x = {}");
  testActionFn.parameter_start_vector();
  testActionFn.parameter_push_back_list(
        std::unique_ptr<List>(new List(vec_data, vec_header_id)));
  testActionFn.parameter_end_vector();

  testActionFnEntry(pkt.get());

  EXPECT_TRUE(logs.contains(
    "x = {3, {'$valid$': 1, 'f16': 1, 'f48': 2}, 5}"));
}

TEST_F(LogTest, InitObjects) {
  fs::path json_path = fs::path(TESTDATADIR) / fs::path("log_msg.json");
  std::ifstream is(json_path.string());
  LookupStructureFactory factory;
  ASSERT_EQ(0, objects.init_objects(&is, &factory));
}
