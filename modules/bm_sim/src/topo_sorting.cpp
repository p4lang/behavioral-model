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

#include "bm_sim/topo_sorting.h"

#include "boost/graph/breadth_first_search.hpp"

void
MyParseGraph::add_edge(header_id_t from, header_id_t to)
{
  vertex_t from_vertex = add_vertex(from);
  vertex_t to_vertex = add_vertex(to);
  boost::add_edge(from_vertex, to_vertex, g0);
}

bool
MyParseGraph::has_vertex(header_id_t header)
{
  auto search = vmap.find(header);
  return (search != vmap.end());
}

MyParseGraph::vertex_t
MyParseGraph::add_vertex(header_id_t header)
{
  auto search = vmap.find(header);
  if(search != vmap.end()) return search->second;
  vertex_t v = boost::add_vertex(g0);
  vmap[header] = v;
  g0[v].header = header;
  return v;
}

class SubgraphBuildVisitor : public boost::default_bfs_visitor
{
  typedef MyParseGraph::vertex_t vertex_t;
  typedef MyParseGraph::Graph Graph;
public:
  SubgraphBuildVisitor(Graph &sub)
    : sub(sub) { }

  void discover_vertex(vertex_t u, const Graph &g) {
    (void) g;
    boost::add_vertex(u, sub);
  }

private:
  Graph &sub;
};

std::vector<header_id_t>
MyParseGraph::get_sorting(header_id_t header) {
  assert(has_vertex(header));
  Graph &sub = g0.create_subgraph();
  SubgraphBuildVisitor vis(sub);
  /* I wanted to use DFS originally, but it was hard to specify a source vertex
     (had to define a color map also) */
  boost::breadth_first_search(g0, boost::vertex(vmap[header], g0),
			      boost::visitor(vis));
  std::vector<header_id_t> sorting;
  typedef std::vector<vertex_t> container;
  container c;
  boost::topological_sort(sub, std::back_inserter(c));
  for(auto rit = c.rbegin(); rit != c.rend(); ++rit) {
    vertex_t gv = sub.local_to_global(*rit);
    sorting.push_back(g0[gv].header);
  }
  return sorting;
}
