/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef BM_BM_SIM_TABLES_H_
#define BM_BM_SIM_TABLES_H_

#include <memory>
#include <string>
#include <utility>

#include "control_flow.h"
#include "match_tables.h"

namespace bm {

// from http://stackoverflow.com/questions/87372/check-if-a-class-has-a-member-function-of-a-given-signature

template<typename T>
struct HasFactoryMethod {
  using Signature = std::unique_ptr<T> (*)(
      const std::string &, const std::string &,
      p4object_id_t, size_t, const MatchKeyBuilder &,
      LookupStructureFactory *,
      bool, bool);

  template <typename U, Signature> struct SFINAE {};
  template<typename U> static char Test(SFINAE<U, U::create>*);
  template<typename U> static int Test(...);
  static const bool value = sizeof(Test<T>(nullptr)) == sizeof(char);
};

class MatchActionTable : public ControlFlowNode {
 public:
  MatchActionTable(const std::string &name, p4object_id_t id,
                   std::unique_ptr<MatchTableAbstract> match_table);

  const ControlFlowNode *operator()(Packet *pkt) const override;

  MatchTableAbstract *get_match_table() { return match_table.get(); }

 public:
  template <typename MT>
  static std::unique_ptr<MatchActionTable> create_match_action_table(
      const std::string &match_type,
      const std::string &name, p4object_id_t id,
      size_t size, const MatchKeyBuilder &match_key_builder,
      bool with_counters, bool with_ageing,
      LookupStructureFactory *lookup_factory) {
    static_assert(
        std::is_base_of<MatchTableAbstract, MT>::value,
        "incorrect template, needs to be a subclass of MatchTableAbstract");

    static_assert(
        HasFactoryMethod<MT>::value,
        "template class needs to have a create() static factory method");

    std::unique_ptr<MT> match_table = MT::create(
      match_type, name, id, size, match_key_builder,
      lookup_factory, with_counters, with_ageing);

    return std::unique_ptr<MatchActionTable>(
      new MatchActionTable(name, id, std::move(match_table)));
  }

 private:
  std::unique_ptr<MatchTableAbstract> match_table;
};

}  // namespace bm

#endif  // BM_BM_SIM_TABLES_H_
