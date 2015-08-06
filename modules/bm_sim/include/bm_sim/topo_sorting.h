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

#ifndef _BM_TOPO_SORTING_H_
#define _BM_TOPO_SORTING_H_

#include <vector>

#include "boost/graph/adjacency_list.hpp"
#include "boost/graph/subgraph.hpp"
#include "boost/graph/topological_sort.hpp"

// for header_id_t definition
#include "phv.h"

class MyParseGraph {
  friend class SubgraphBuildVisitor; // forward declaration
public:
  void add_edge(header_id_t from, header_id_t to);
  std::vector<header_id_t> get_sorting(header_id_t header);

private:
  struct Vertex {
    header_id_t header;
  };

  struct Edge {
  };

private:
  typedef boost::property<boost::vertex_index_t, int, Vertex> vertex_prop;
  typedef boost::property<boost::edge_index_t, int, Edge> edge_prop;
  typedef boost::adjacency_list<boost::setS, boost::vecS, boost::directedS,
				vertex_prop, edge_prop> Traits;
  typedef boost::subgraph<Traits> Graph;
  typedef boost::graph_traits<Graph>::vertex_descriptor vertex_t;
  typedef boost::graph_traits<Graph>::edge_descriptor edge_t;
  typedef boost::graph_traits<Graph>::vertex_iterator vertex_iter;
  typedef boost::graph_traits<Graph>::edge_iterator edge_iter;

private:
  bool has_vertex(header_id_t header);
  vertex_t add_vertex(header_id_t header);

private:
  Graph g0{};
  // could investigate boost::labeled_graph but does not look like it is worth
  // the trouble
  std::unordered_map<header_id_t, vertex_t> vmap{};
};

#endif
