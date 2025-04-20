#include <gtest/gtest.h>

#include <bm/bm_sim/P4Objects.h>
#include <bm/bm_sim/table_apply.h>

#include <string>
#include <memory>
#include <vector>
#include <algorithm>

#include <boost/filesystem.hpp>

#include "jsoncpp/json.h"

using namespace bm;

namespace fs = boost::filesystem;

namespace {

// Sample JSON for testing table_applies
const std::string JSON_TEST_STRING_TABLE_APPLIES = R"(
{
  "__meta__": {
    "version": [3, 0]
  },
  "header_types": [
    {
      "name": "standard_metadata_t",
      "id": 0,
      "fields": [
        ["ingress_port", 9],
        ["packet_length", 32],
        ["egress_spec", 9],
        ["egress_port", 9],
        ["instance_type", 32],
        ["clone_spec", 32],
        ["_padding", 5]
      ]
    },
    {
      "name": "ethernet_t",
      "id": 1,
      "fields": [
        ["dstAddr", 48],
        ["srcAddr", 48],
        ["etherType", 16]
      ]
    }
  ],
  "headers": [
    {
      "name": "standard_metadata",
      "id": 0,
      "header_type": "standard_metadata_t",
      "metadata": true,
      "pi_omit": true
    },
    {
      "name": "ethernet",
      "id": 1,
      "header_type": "ethernet_t",
      "metadata": false,
      "pi_omit": true
    }
  ],
  "actions": [
    {
      "name": "act1",
      "id": 0,
      "runtime_data": [],
      "primitives": []
    },
    {
      "name": "act2",
      "id": 1,
      "runtime_data": [],
      "primitives": []
    }
  ],
  "pipelines": [
    {
      "name": "ingress",
      "id": 0,
      "init_table": "table_apply_1",
      "tables": [
        {
          "name": "table1",
          "id": 0,
          "match_type": "exact",
          "type": "simple",
          "max_size": 1024,
          "with_counters": false,
          "key": [
            {
              "match_type": "exact",
              "target": ["ethernet", "dstAddr"],
              "mask": null
            }
          ],
          "actions": ["act1", "act2"],
          "default_entry": {
            "action_id": 0,
            "action_const": false,
            "action_data": [],
            "action_entry_const": false
          }
        }
      ],
      "table_applies": [
        {
          "name": "table_apply_1",
          "id": 0,
          "table": "table1",
          "next_tables": {
            "__HIT__": "table_apply_2",
            "__MISS__": null
          }
        },
        {
          "name": "table_apply_2",
          "id": 1,
          "table": "table1",
          "next_tables": {
            "__HIT__": null,
            "__MISS__": null
          }
        }
      ],
      "conditionals": []
    },
    {
      "name": "egress",
      "id": 1,
      "init_table": null,
      "tables": [],
      "conditionals": []
    }
  ],
  "calculations": [],
  "checksums": [],
  "learn_lists": [],
  "field_lists": [],
  "counter_arrays": [],
  "register_arrays": [],
  "meter_arrays": [],
  "externs": [],
  "parsers": [
    {
      "name": "parser",
      "id": 0,
      "init_state": "start",
      "parse_states": [
        {
          "name": "start",
          "id": 0,
          "parser_ops": [
            {
              "parameters": [
                {
                  "type": "regular",
                  "value": "ethernet"
                }
              ],
              "op": "extract"
            }
          ],
          "transition_key": [],
          "transitions": [
            {
              "type": "default",
              "value": null,
              "mask": null,
              "next_state": null
            }
          ]
        }
      ]
    }
  ],
  "deparsers": [
    {
      "name": "deparser",
      "id": 0,
      "order": ["ethernet"]
    }
  ]
}
)";

}  // namespace

class TableApplyTest : public ::testing::Test {
 protected:
  PHVFactory phv_factory;

  void SetUp() override {}

  std::unique_ptr<P4Objects> parse_json(const std::string &json_str) {
    std::stringstream ss(json_str);
    auto objects = std::unique_ptr<P4Objects>(new P4Objects());
    LookupStructureFactory factory;
    EXPECT_EQ(0, objects->init_objects(&ss, &factory));
    return objects;
  }
};

TEST_F(TableApplyTest, TableApplies) {
  auto objects = parse_json(JSON_TEST_STRING_TABLE_APPLIES);

  // Check that the table_applies were parsed correctly
  auto table_apply_1 = objects->get_table_apply("table_apply_1");
  auto table_apply_2 = objects->get_table_apply("table_apply_2");

  ASSERT_NE(nullptr, table_apply_1);
  ASSERT_NE(nullptr, table_apply_2);

  // Check that both table_applies reference the same table
  EXPECT_EQ(table_apply_1->get_table(), table_apply_2->get_table());

  // Check that the pipeline was set up correctly
  auto pipeline = objects->get_pipeline("ingress");
  ASSERT_NE(nullptr, pipeline);

  // The first node in the pipeline should be table_apply_1
  EXPECT_EQ("table_apply_1", pipeline->get_first_node()->get_name());
}
