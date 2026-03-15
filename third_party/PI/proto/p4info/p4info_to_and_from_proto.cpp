/* Copyright 2013-present Barefoot Networks, Inc.
 * SPDX-License-Identifier: Apache-2.0
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

#include <PI/p4info.h>

#include <exception>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "p4info_int.h"

#include "PI/proto/p4info_to_and_from_proto.h"

#include "p4/config/v1/p4info.pb.h"

namespace p4configv1 = ::p4::config::v1;

namespace pi {

namespace p4info {

// proto -> p4info

namespace {

// only used internally, not exposed in the header
class read_proto_exception : public std::exception {
 public:
  explicit read_proto_exception(const std::string &msg)
      : msg(msg) { }

  const char* what() const noexcept override {
    return msg.c_str();
  }

 private:
  std::string msg;
};

void import_annotations(const p4configv1::Preamble &pre, pi_p4info_t *p4info) {
  for (const auto &annotation : pre.annotations())
    pi_p4info_add_annotation(p4info, pre.id(), annotation.c_str());
}

void import_alias(const p4configv1::Preamble &pre, pi_p4info_t *p4info) {
  pi_p4info_add_alias(p4info, pre.id(), pre.alias().c_str());
}

void import_common(const p4configv1::Preamble &pre, pi_p4info_t *p4info) {
  import_annotations(pre, p4info);
  import_alias(pre, p4info);
}

void read_actions(const p4configv1::P4Info &p4info_proto, pi_p4info_t *p4info) {
  const auto &actions = p4info_proto.actions();
  pi_p4info_action_init(p4info, actions.size());
  for (const auto &action : actions) {
    const auto &pre = action.preamble();
    pi_p4info_action_add(p4info, pre.id(), pre.name().c_str(),
                         action.params().size());
    for (const auto &param : action.params()) {
      pi_p4info_action_add_param(p4info, pre.id(), param.id(),
                                 param.name().c_str(), param.bitwidth());
    }
    import_common(pre, p4info);
  }
}

void read_tables(const p4configv1::P4Info &p4info_proto, pi_p4info_t *p4info) {
  const auto &tables = p4info_proto.tables();
  pi_p4info_table_init(p4info, tables.size());
  for (const auto &table : tables) {
    const auto &pre = table.preamble();
    bool supports_idle_timeout =
        (table.idle_timeout_behavior() == p4configv1::Table::NOTIFY_CONTROL);
    pi_p4info_table_add(p4info, pre.id(), pre.name().c_str(),
                        table.match_fields().size(), table.action_refs().size(),
                        table.size(), table.is_const_table(),
                        supports_idle_timeout);

    for (const auto &mf : table.match_fields()) {
      auto match_type_convert = [&mf]() {
        switch (mf.match_type()) {
          case p4configv1::MatchField_MatchType_EXACT:
            return PI_P4INFO_MATCH_TYPE_EXACT;
          case p4configv1::MatchField_MatchType_LPM:
            return PI_P4INFO_MATCH_TYPE_LPM;
          case p4configv1::MatchField_MatchType_TERNARY:
            return PI_P4INFO_MATCH_TYPE_TERNARY;
          case p4configv1::MatchField_MatchType_RANGE:
            return PI_P4INFO_MATCH_TYPE_RANGE;
          case p4configv1::MatchField_MatchType_OPTIONAL:
            return PI_P4INFO_MATCH_TYPE_OPTIONAL;
          default:  // invalid
            throw read_proto_exception("Invalid match type");
        }
      };

      pi_p4info_table_add_match_field(
          p4info, pre.id(), mf.id(), mf.name().c_str(), match_type_convert(),
          mf.bitwidth());
    }

    for (const auto &action_ref : table.action_refs()) {
      auto scope_convert = [&action_ref]() {
        switch (action_ref.scope()) {
          case p4configv1::ActionRef::TABLE_AND_DEFAULT:
            return PI_P4INFO_ACTION_SCOPE_TABLE_AND_DEFAULT;
          case p4configv1::ActionRef::TABLE_ONLY:
            return PI_P4INFO_ACTION_SCOPE_TABLE_ONLY;
          case p4configv1::ActionRef::DEFAULT_ONLY:
            return PI_P4INFO_ACTION_SCOPE_DEFAULT_ONLY;
          default:
            throw read_proto_exception("Invalid action scope");
        }
      };
      pi_p4info_table_add_action(
          p4info, pre.id(), action_ref.id(), scope_convert());
      // TODO(antonin): ignoring action ref annotations for now
    }

    if (table.const_default_action_id() != PI_INVALID_ID) {
      pi_p4info_table_set_const_default_action(
          p4info, pre.id(), table.const_default_action_id());
    }

    if (table.implementation_id() != PI_INVALID_ID) {
      pi_p4info_table_set_implementation(p4info, pre.id(),
                                         table.implementation_id());
    }

    for (const auto &direct_res_id : table.direct_resource_ids())
      pi_p4info_table_add_direct_resource(p4info, pre.id(), direct_res_id);

    import_common(pre, p4info);
  }
}

void read_act_profs(const p4configv1::P4Info &p4info_proto,
                    pi_p4info_t *p4info) {
  const auto &action_profiles = p4info_proto.action_profiles();
  pi_p4info_act_prof_init(p4info, action_profiles.size());
  for (const auto &act_prof : action_profiles) {
    const auto &pre = act_prof.preamble();
    pi_p4info_act_prof_add(p4info, pre.id(), pre.name().c_str(),
                           act_prof.with_selector(), act_prof.size());
    for (const auto table_id : act_prof.table_ids())
      pi_p4info_act_prof_add_table(p4info, pre.id(), table_id);

    pi_p4info_act_prof_set_max_grp_size(
        p4info, pre.id(), act_prof.max_group_size());

    import_common(pre, p4info);
  }
}

void read_counters(const p4configv1::P4Info &p4info_proto,
                   pi_p4info_t *p4info) {
  const auto &counters = p4info_proto.counters();
  const auto &direct_counters = p4info_proto.direct_counters();

  auto unit_convert = [](const p4configv1::CounterSpec &spec) {
    switch (spec.unit()) {
      case p4configv1::CounterSpec_Unit_BYTES:
        return PI_P4INFO_COUNTER_UNIT_BYTES;
      case p4configv1::CounterSpec_Unit_PACKETS:
        return PI_P4INFO_COUNTER_UNIT_PACKETS;
      case p4configv1::CounterSpec_Unit_BOTH:
        return PI_P4INFO_COUNTER_UNIT_BOTH;
      default:  // invalid
        throw read_proto_exception("Invalid counter unit");
    }
  };

  pi_p4info_counter_init(p4info, counters.size());
  for (const auto &counter : counters) {
    const auto &pre = counter.preamble();
    pi_p4info_counter_add(p4info, pre.id(), pre.name().c_str(),
                          unit_convert(counter.spec()), counter.size());
    import_common(pre, p4info);
  }
  pi_p4info_direct_counter_init(p4info, direct_counters.size());
  for (const auto &counter : direct_counters) {
    const auto &pre = counter.preamble();
    // TODO(antonin): use actual table size instead of 0?
    pi_p4info_direct_counter_add(p4info, pre.id(), pre.name().c_str(),
                                 unit_convert(counter.spec()), 0  /* size */,
                                 counter.direct_table_id());
    import_common(pre, p4info);
  }
}

void read_meters(const p4configv1::P4Info &p4info_proto, pi_p4info_t *p4info) {
  const auto &meters = p4info_proto.meters();
  const auto &direct_meters = p4info_proto.direct_meters();

  auto unit_convert = [](const p4configv1::MeterSpec &spec) {
    switch (spec.unit()) {
      case p4configv1::MeterSpec_Unit_BYTES:
        return PI_P4INFO_METER_UNIT_BYTES;
      case p4configv1::MeterSpec_Unit_PACKETS:
        return PI_P4INFO_METER_UNIT_PACKETS;
      default:  // invalid
        throw read_proto_exception("Invalid meter unit");
    }
  };

  // P4Info no longer includes information about color-awareness: in PSA
  // color-awareness is a parameter to the the meter execute call, not a
  // property of the meter extern

  pi_p4info_meter_init(p4info, meters.size());
  for (const auto &meter : meters) {
    const auto &pre = meter.preamble();
    pi_p4info_meter_add(p4info, pre.id(), pre.name().c_str(),
                        unit_convert(meter.spec()),
                        PI_P4INFO_METER_TYPE_COLOR_UNAWARE,
                        meter.size());
    import_common(pre, p4info);
  }
  pi_p4info_direct_meter_init(p4info, direct_meters.size());
  for (const auto &meter : direct_meters) {
    const auto &pre = meter.preamble();
    // TODO(antonin): use actual table size instead of 0?
    pi_p4info_direct_meter_add(p4info, pre.id(), pre.name().c_str(),
                               unit_convert(meter.spec()),
                               PI_P4INFO_METER_TYPE_COLOR_UNAWARE,
                               0  /* size */,
                               meter.direct_table_id());
    import_common(pre, p4info);
  }
}

struct DigestField {
  std::string name;
  size_t bitwidth;
};

std::vector<DigestField>
convert_type_spec_to_digest_fields(const p4configv1::P4DataTypeSpec &type_spec,
                                   const p4configv1::P4TypeInfo &type_info) {
  std::vector<DigestField> digest_fields;

  auto addField = [&](const std::string &name,
                      const p4configv1::P4DataTypeSpec& fSpec) {
    if (!fSpec.has_bitstring() || !fSpec.bitstring().has_bit())
      throw read_proto_exception("Packed type for digest too complex");
    auto &bit_type_spec = fSpec.bitstring().bit();
    if (bit_type_spec.bitwidth() < 0)
      throw read_proto_exception("Negative bitwidth in type spec");
    auto bitwidth = static_cast<size_t>(bit_type_spec.bitwidth());
    digest_fields.push_back({name, bitwidth});
  };

  if (type_spec.has_struct_()) {
    auto structName = type_spec.struct_().name();
    auto p_it = type_info.structs().find(structName);
    if (p_it == type_info.structs().end())
      throw read_proto_exception("Struct name not found in P4Info map");
    for (const auto& member : p_it->second.members())
      addField(member.name(), member.type_spec());
  } else if (type_spec.has_tuple()) {
    for (const auto& member : type_spec.tuple().members())
      addField("", member);  // members of tuple are unnamed
  } else if (type_spec.has_bitstring()) {
    addField("", type_spec);
  } else {
    throw read_proto_exception("Packed type for digest too complex");
  }

  return digest_fields;
}

void read_digests(const p4configv1::P4Info &p4info_proto, pi_p4info_t *p4info) {
  const auto &digests = p4info_proto.digests();
  pi_p4info_digest_init(p4info, digests.size());
  for (const auto &digest : digests) {
    const auto &pre = digest.preamble();
    auto digest_fields = convert_type_spec_to_digest_fields(
        digest.type_spec(), p4info_proto.type_info());
    pi_p4info_digest_add(p4info, pre.id(), pre.name().c_str(),
                         digest_fields.size());
    for (const auto &f : digest_fields)
      pi_p4info_digest_add_field(p4info, pre.id(), f.name.c_str(), f.bitwidth);
    import_common(pre, p4info);
  }
}

}  // namespace

bool p4info_proto_reader(const p4configv1::P4Info &p4info_proto,
                         pi_p4info_t **p4info) {
  pi_empty_config(p4info);
  try {
    read_actions(p4info_proto, *p4info);
    read_tables(p4info_proto, *p4info);
    read_act_profs(p4info_proto, *p4info);
    read_counters(p4info_proto, *p4info);
    read_meters(p4info_proto, *p4info);
    read_digests(p4info_proto, *p4info);
  } catch (const read_proto_exception &e) {
    std::cerr << e.what() << "\n";
    return false;
  }
  return true;
}

// p4info -> proto

namespace {

template <typename T>
void set_preamble(T *obj, pi_p4_id_t id, const char *name,
                  const pi_p4info_t *p4info) {
  auto pre = obj->mutable_preamble();
  pre->set_id(id);
  pre->set_name(name);
  size_t num_annotations;
  auto annotations = pi_p4info_get_annotations(p4info, id, &num_annotations);
  for (size_t i = 0; i < num_annotations; i++)
    pre->add_annotations(annotations[i]);
  size_t num_aliases;
  auto aliases = pi_p4info_get_aliases(p4info, id, &num_aliases);
  // TODO(antonin): warn if more than one alias
  if (num_aliases > 0) pre->set_alias(aliases[0]);
}

void p4info_serialize_actions(const pi_p4info_t *p4info,
                              p4configv1::P4Info *p4info_proto) {
  for (auto id = pi_p4info_action_begin(p4info);
       id != pi_p4info_action_end(p4info);
       id = pi_p4info_action_next(p4info, id)) {
    auto action = p4info_proto->add_actions();
    auto name = pi_p4info_action_name_from_id(p4info, id);
    set_preamble(action, id, name, p4info);
    size_t num_params;
    auto param_ids = pi_p4info_action_get_params(p4info, id, &num_params);
    for (size_t i = 0; i < num_params; i++) {
      auto param = action->add_params();
      auto param_id = param_ids[i];
      param->set_id(param_id);
      param->set_name(
          pi_p4info_action_param_name_from_id(p4info, id, param_id));
      param->set_bitwidth(
          pi_p4info_action_param_bitwidth(p4info, id, param_id));
    }
  }
}

void p4info_serialize_tables(const pi_p4info_t *p4info,
                             p4configv1::P4Info *p4info_proto) {
  for (auto id = pi_p4info_table_begin(p4info);
       id != pi_p4info_table_end(p4info);
       id = pi_p4info_table_next(p4info, id)) {
    auto table = p4info_proto->add_tables();
    auto name = pi_p4info_table_name_from_id(p4info, id);
    set_preamble(table, id, name, p4info);

    size_t num_match_fields;
    auto match_field_ids = pi_p4info_table_get_match_fields(p4info, id,
                                                            &num_match_fields);
    for (size_t i = 0; i < num_match_fields; i++) {
      auto mf = table->add_match_fields();
      auto mf_id = match_field_ids[i];
      auto info = pi_p4info_table_match_field_info(p4info, id, i);
      assert(mf_id == info->mf_id);
      mf->set_id(mf_id);
      auto match_type_convert = [info]() {
        switch (info->match_type) {
          // A P4_14 valid match type is replaced by an exact match in the
          // P4Info, since P4Runtime no longer supports the valid matches, which
          // no longer exist in P4_16. The new p4c compiler always translates
          // P4_14 programs to P4_16 before generating P4Info, which replaces
          // all valid matches with exact matches on the validity bit.
          case PI_P4INFO_MATCH_TYPE_VALID:
          case PI_P4INFO_MATCH_TYPE_EXACT:
            return p4configv1::MatchField_MatchType_EXACT;
          case PI_P4INFO_MATCH_TYPE_LPM:
            return p4configv1::MatchField_MatchType_LPM;
          case PI_P4INFO_MATCH_TYPE_TERNARY:
            return p4configv1::MatchField_MatchType_TERNARY;
          case PI_P4INFO_MATCH_TYPE_RANGE:
            return p4configv1::MatchField_MatchType_RANGE;
          case PI_P4INFO_MATCH_TYPE_OPTIONAL:
            return p4configv1::MatchField_MatchType_OPTIONAL;
          default:
            return p4configv1::MatchField_MatchType_UNSPECIFIED;
        }
      };
      mf->set_match_type(match_type_convert());
      mf->set_name(info->name);
      mf->set_bitwidth(info->bitwidth);
    }

    size_t num_actions;
    auto action_ids = pi_p4info_table_get_actions(p4info, id, &num_actions);
    for (size_t i = 0; i < num_actions; i++) {
      auto action_ref = table->add_action_refs();
      auto action_info = pi_p4info_table_get_action_info(
          p4info, id, action_ids[i]);
      assert(action_info);
      auto scope_convert = [action_info]() {
        switch (action_info->scope) {
          case PI_P4INFO_ACTION_SCOPE_TABLE_AND_DEFAULT:
            return p4configv1::ActionRef::TABLE_AND_DEFAULT;
          case PI_P4INFO_ACTION_SCOPE_TABLE_ONLY:
            return p4configv1::ActionRef::TABLE_ONLY;
          case PI_P4INFO_ACTION_SCOPE_DEFAULT_ONLY:
            return p4configv1::ActionRef::DEFAULT_ONLY;
          default:
            throw read_proto_exception("Invalid action scope");
        }
      };
      action_ref->set_id(action_ids[i]);
      action_ref->set_scope(scope_convert());
      // TODO(antonin): p4info C struct does not store action ref annotations
    }

    bool has_mutable_action_params;
    auto const_default_action_id = pi_p4info_table_get_const_default_action(
        p4info, id, &has_mutable_action_params);
    table->set_const_default_action_id(const_default_action_id);

    table->set_implementation_id(
        pi_p4info_table_get_implementation(p4info, id));

    size_t num_direct_resources;
    auto direct_res_ids = pi_p4info_table_get_direct_resources(
        p4info, id, &num_direct_resources);
    for (size_t i = 0; i < num_direct_resources; i++)
      table->add_direct_resource_ids(direct_res_ids[i]);

    table->set_size(pi_p4info_table_max_size(p4info, id));

    table->set_is_const_table(pi_p4info_table_is_const(p4info, id));

    bool supports_idle_timeout = pi_p4info_table_supports_idle_timeout(
        p4info, id);
    table->set_idle_timeout_behavior(
        supports_idle_timeout ?
            p4configv1::Table::NOTIFY_CONTROL : p4configv1::Table::NO_TIMEOUT);
  }
}

void p4info_serialize_act_profs(const pi_p4info_t *p4info,
                                p4configv1::P4Info *p4info_proto) {
  for (auto id = pi_p4info_act_prof_begin(p4info);
       id != pi_p4info_act_prof_end(p4info);
       id = pi_p4info_act_prof_next(p4info, id)) {
    auto act_prof = p4info_proto->add_action_profiles();
    auto name = pi_p4info_act_prof_name_from_id(p4info, id);
    set_preamble(act_prof, id, name, p4info);
    size_t num_tables;
    auto table_ids = pi_p4info_act_prof_get_tables(p4info, id, &num_tables);
    for (size_t i = 0; i < num_tables; i++)
      act_prof->add_table_ids(table_ids[i]);
    act_prof->set_with_selector(pi_p4info_act_prof_has_selector(p4info, id));
    act_prof->set_size(pi_p4info_act_prof_max_size(p4info, id));
    act_prof->set_max_group_size(pi_p4info_act_prof_max_grp_size(p4info, id));
  }
}

template <typename T>
void serialize_one_counter(const pi_p4info_t *p4info, pi_p4_id_t id,
                           T *counter) {
  auto unit_convert = [](pi_p4info_counter_unit_t unit) {
    switch (unit) {
      case PI_P4INFO_COUNTER_UNIT_BYTES:
        return p4configv1::CounterSpec_Unit_BYTES;
      case PI_P4INFO_COUNTER_UNIT_PACKETS:
        return p4configv1::CounterSpec_Unit_PACKETS;
      case PI_P4INFO_COUNTER_UNIT_BOTH:
        return p4configv1::CounterSpec_Unit_BOTH;
      default:  // invalid
        return p4configv1::CounterSpec_Unit_UNSPECIFIED;
    }
  };

  auto set_spec = [p4info, id, &unit_convert](p4configv1::CounterSpec *spec) {
    auto unit = pi_p4info_counter_get_unit(p4info, id);
    spec->set_unit(unit_convert(unit));
  };

  auto name = pi_p4info_counter_name_from_id(p4info, id);
  set_preamble(counter, id, name, p4info);
  set_spec(counter->mutable_spec());
}

void p4info_serialize_counters(const pi_p4info_t *p4info,
                               p4configv1::P4Info *p4info_proto) {
  for (auto id = pi_p4info_counter_begin(p4info);
       id != pi_p4info_counter_end(p4info);
       id = pi_p4info_counter_next(p4info, id)) {
    auto *counter = p4info_proto->add_counters();
    serialize_one_counter(p4info, id, counter);
    counter->set_size(pi_p4info_counter_get_size(p4info, id));
  }
  for (auto id = pi_p4info_direct_counter_begin(p4info);
       id != pi_p4info_direct_counter_end(p4info);
       id = pi_p4info_direct_counter_next(p4info, id)) {
    auto *counter = p4info_proto->add_direct_counters();
    serialize_one_counter(p4info, id, counter);
    auto t_id = pi_p4info_counter_get_direct(p4info, id);
    counter->set_direct_table_id(t_id);
  }
}

template <typename T>
void serialize_one_meter(const pi_p4info_t *p4info, pi_p4_id_t id, T *meter) {
  auto unit_convert = [](pi_p4info_meter_unit_t unit) {
    switch (unit) {
      case PI_P4INFO_METER_UNIT_BYTES:
        return p4configv1::MeterSpec_Unit_BYTES;
      case PI_P4INFO_METER_UNIT_PACKETS:
        return p4configv1::MeterSpec_Unit_PACKETS;
      default:  // invalid
        return p4configv1::MeterSpec_Unit_UNSPECIFIED;
    }
  };

  auto set_spec = [p4info, id, &unit_convert](
      p4configv1::MeterSpec *spec) {
    auto unit = pi_p4info_meter_get_unit(p4info, id);
    spec->set_unit(unit_convert(unit));
  };

  auto name = pi_p4info_meter_name_from_id(p4info, id);
  set_preamble(meter, id, name, p4info);
  set_spec(meter->mutable_spec());
}

void p4info_serialize_meters(const pi_p4info_t *p4info,
                             p4configv1::P4Info *p4info_proto) {
  for (auto id = pi_p4info_meter_begin(p4info);
       id != pi_p4info_meter_end(p4info);
       id = pi_p4info_meter_next(p4info, id)) {
    auto meter = p4info_proto->add_meters();
    serialize_one_meter(p4info, id, meter);
    meter->set_size(pi_p4info_meter_get_size(p4info, id));
  }
  for (auto id = pi_p4info_direct_meter_begin(p4info);
       id != pi_p4info_direct_meter_end(p4info);
       id = pi_p4info_direct_meter_next(p4info, id)) {
    auto meter = p4info_proto->add_direct_meters();
    serialize_one_meter(p4info, id, meter);
    auto t_id = pi_p4info_meter_get_direct(p4info, id);
    meter->set_direct_table_id(t_id);
  }
}

// This method always serializes digests using P4TupleTypeSpec which breaks
// symmetry if one first converts from P4Info (Protobuf) to pi_p4info_t and then
// back to P4Info.
void p4info_serialize_digests(const pi_p4info_t *p4info,
                              p4configv1::P4Info *p4info_proto) {
  for (auto id = pi_p4info_digest_begin(p4info);
       id != pi_p4info_digest_end(p4info);
       id = pi_p4info_digest_next(p4info, id)) {
    auto digest = p4info_proto->add_digests();
    auto name = pi_p4info_digest_name_from_id(p4info, id);
    set_preamble(digest, id, name, p4info);
    auto tuple_spec = digest->mutable_type_spec()->mutable_tuple();
    auto num_fields = pi_p4info_digest_num_fields(p4info, id);
    for (size_t idx = 0; idx < num_fields; idx++) {
      // auto f_name = pi_p4info_digest_field_name(p4info, id, idx);
      auto bitwidth = pi_p4info_digest_field_bitwidth(p4info, id, idx);
      auto bit_type_spec =
          tuple_spec->add_members()->mutable_bitstring()->mutable_bit();
      bit_type_spec->set_bitwidth(bitwidth);
    }
  }
}

}  // namespace

p4configv1::P4Info p4info_serialize_to_proto(const pi_p4info_t *p4info) {
  p4configv1::P4Info p4info_proto;
  p4info_serialize_actions(p4info, &p4info_proto);
  p4info_serialize_tables(p4info, &p4info_proto);
  p4info_serialize_act_profs(p4info, &p4info_proto);
  p4info_serialize_counters(p4info, &p4info_proto);
  p4info_serialize_meters(p4info, &p4info_proto);
  p4info_serialize_digests(p4info, &p4info_proto);
  return p4info_proto;
}

}  // namespace p4info

}  // namespace pi
