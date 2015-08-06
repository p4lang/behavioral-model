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

#include "bm_sim/topo_sorting.h"

TEST(TopoSorting, SimpleTest) {
  /*
    0+----->1+----->2+----->4
            +       ^       +
            |       |       |
            |       |       |
            v       |       v
            3+------+       5
  */
  MyParseGraph graph;
  graph.add_edge(0, 1);
  graph.add_edge(1, 2);
  graph.add_edge(1, 3);
  graph.add_edge(2, 4);
  graph.add_edge(3, 2);
  graph.add_edge(4, 5);

  std::vector<header_id_t> sorting1 = graph.get_sorting(1);
  std::vector<header_id_t> sorting2 = graph.get_sorting(2);
  ASSERT_EQ(std::vector<header_id_t>({1, 3, 2, 4, 5}), sorting1);
  ASSERT_EQ(std::vector<header_id_t>({2, 4, 5}), sorting2);
}
