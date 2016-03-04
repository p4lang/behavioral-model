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

#include "bm_sim/context.h"

#include <string>
#include <vector>
#include <set>

namespace bm {

Context::Context() {
  p4objects = std::make_shared<P4Objects>();
  p4objects_rt = p4objects;
}

// ---------- runtime interfaces ----------

MatchErrorCode
Context::mt_add_entry(const std::string &table_name,
                      const std::vector<MatchKeyParam> &match_key,
                      const std::string &action_name,
                      ActionData action_data,
                      entry_handle_t *handle,
                      int priority) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  MatchTableAbstract *abstract_table =
    p4objects_rt->get_abstract_match_table(table_name);
  assert(abstract_table);
  MatchTable *table = dynamic_cast<MatchTable *>(abstract_table);
  if (!table) return MatchErrorCode::WRONG_TABLE_TYPE;
  const ActionFn *action = p4objects_rt->get_action(action_name);
  assert(action);
  return table->add_entry(
    match_key, action, std::move(action_data), handle, priority);
}

MatchErrorCode
Context::mt_set_default_action(const std::string &table_name,
                               const std::string &action_name,
                               ActionData action_data) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  MatchTableAbstract *abstract_table =
    p4objects_rt->get_abstract_match_table(table_name);
  assert(abstract_table);
  MatchTable *table = dynamic_cast<MatchTable *>(abstract_table);
  if (!table) return MatchErrorCode::WRONG_TABLE_TYPE;
  const ActionFn *action = p4objects_rt->get_action(action_name);
  assert(action);
  return table->set_default_action(action, std::move(action_data));
}

MatchErrorCode
Context::mt_delete_entry(const std::string &table_name,
                         entry_handle_t handle) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  MatchTableAbstract *abstract_table =
    p4objects_rt->get_abstract_match_table(table_name);
  assert(abstract_table);
  MatchTable *table = dynamic_cast<MatchTable *>(abstract_table);
  if (!table) return MatchErrorCode::WRONG_TABLE_TYPE;
  return table->delete_entry(handle);
}

MatchErrorCode
Context::mt_modify_entry(const std::string &table_name,
                         entry_handle_t handle,
                         const std::string &action_name,
                         const ActionData action_data) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  MatchTableAbstract *abstract_table =
    p4objects_rt->get_abstract_match_table(table_name);
  assert(abstract_table);
  MatchTable *table = dynamic_cast<MatchTable *>(abstract_table);
  if (!table) return MatchErrorCode::WRONG_TABLE_TYPE;
  const ActionFn *action = p4objects_rt->get_action(action_name);
  assert(action);
  return table->modify_entry(handle, action, std::move(action_data));
}

MatchErrorCode
Context::mt_set_entry_ttl(const std::string &table_name,
                          entry_handle_t handle,
                          unsigned int ttl_ms) {
  MatchTableAbstract *abstract_table =
    p4objects_rt->get_abstract_match_table(table_name);
  if (!abstract_table) return MatchErrorCode::INVALID_TABLE_NAME;
  return abstract_table->set_entry_ttl(handle, ttl_ms);
}

MatchErrorCode
Context::get_mt_indirect(
    const std::string &table_name, MatchTableIndirect **table
) {
  MatchTableAbstract *abstract_table =
    p4objects_rt->get_abstract_match_table(table_name);
  if (!abstract_table) return MatchErrorCode::INVALID_TABLE_NAME;
  *table = dynamic_cast<MatchTableIndirect *>(abstract_table);
  if (!(*table)) return MatchErrorCode::WRONG_TABLE_TYPE;
  return MatchErrorCode::SUCCESS;
}

MatchErrorCode
Context::mt_indirect_add_member(
    const std::string &table_name, const std::string &action_name,
    ActionData action_data, mbr_hdl_t *mbr) {
  MatchErrorCode rc;
  MatchTableIndirect *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  const ActionFn *action = p4objects_rt->get_action(action_name);
  if (!action) return MatchErrorCode::INVALID_ACTION_NAME;
  return table->add_member(action, std::move(action_data), mbr);
}

MatchErrorCode
Context::mt_indirect_delete_member(const std::string &table_name,
                                   mbr_hdl_t mbr) {
  MatchErrorCode rc;
  MatchTableIndirect *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  return table->delete_member(mbr);
}

MatchErrorCode
Context::mt_indirect_modify_member(const std::string &table_name,
                                   mbr_hdl_t mbr,
                                   const std::string &action_name,
                                   ActionData action_data) {
  MatchErrorCode rc;
  MatchTableIndirect *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  const ActionFn *action = p4objects_rt->get_action(action_name);
  if (!action) return MatchErrorCode::INVALID_ACTION_NAME;
  return table->modify_member(mbr, action, std::move(action_data));
}

MatchErrorCode
Context::mt_indirect_add_entry(
    const std::string &table_name,
    const std::vector<MatchKeyParam> &match_key,
    mbr_hdl_t mbr, entry_handle_t *handle, int priority) {
  MatchErrorCode rc;
  MatchTableIndirect *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  return table->add_entry(match_key, mbr, handle, priority);
}

MatchErrorCode
Context::mt_indirect_modify_entry(const std::string &table_name,
                                  entry_handle_t handle,
                                  mbr_hdl_t mbr) {
  MatchErrorCode rc;
  MatchTableIndirect *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  return table->modify_entry(handle, mbr);
}

MatchErrorCode
Context::mt_indirect_delete_entry(const std::string &table_name,
                                  entry_handle_t handle) {
  MatchErrorCode rc;
  MatchTableIndirect *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  return table->delete_entry(handle);
}

MatchErrorCode
Context::mt_indirect_set_entry_ttl(const std::string &table_name,
                                   entry_handle_t handle,
                                   unsigned int ttl_ms) {
  MatchTableAbstract *abstract_table =
    p4objects_rt->get_abstract_match_table(table_name);
  if (!abstract_table) return MatchErrorCode::INVALID_TABLE_NAME;
  return abstract_table->set_entry_ttl(handle, ttl_ms);
}

MatchErrorCode
Context::mt_indirect_set_default_member(const std::string &table_name,
                                        mbr_hdl_t mbr) {
  MatchErrorCode rc;
  MatchTableIndirect *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  return table->set_default_member(mbr);
}

MatchErrorCode
Context::get_mt_indirect_ws(const std::string &table_name,
                            MatchTableIndirectWS **table) {
  MatchTableAbstract *abstract_table =
    p4objects_rt->get_abstract_match_table(table_name);
  if (!abstract_table) return MatchErrorCode::INVALID_TABLE_NAME;
  *table = dynamic_cast<MatchTableIndirectWS *>(abstract_table);
  if (!(*table)) return MatchErrorCode::WRONG_TABLE_TYPE;
  return MatchErrorCode::SUCCESS;
}

MatchErrorCode
Context::mt_indirect_ws_create_group(const std::string &table_name,
                                     grp_hdl_t *grp) {
  MatchErrorCode rc;
  MatchTableIndirectWS *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect_ws(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  return table->create_group(grp);
}

MatchErrorCode
Context::mt_indirect_ws_delete_group(const std::string &table_name,
                                     grp_hdl_t grp) {
  MatchErrorCode rc;
  MatchTableIndirectWS *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect_ws(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  return table->delete_group(grp);
}

MatchErrorCode
Context::mt_indirect_ws_add_member_to_group(
    const std::string &table_name, mbr_hdl_t mbr, grp_hdl_t grp) {
  MatchErrorCode rc;
  MatchTableIndirectWS *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect_ws(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  return table->add_member_to_group(mbr, grp);
}

MatchErrorCode
Context::mt_indirect_ws_remove_member_from_group(
    const std::string &table_name,
    mbr_hdl_t mbr, grp_hdl_t grp) {
  MatchErrorCode rc;
  MatchTableIndirectWS *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect_ws(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  return table->remove_member_from_group(mbr, grp);
}

MatchErrorCode
Context::mt_indirect_ws_add_entry(
    const std::string &table_name,
    const std::vector<MatchKeyParam> &match_key,
    grp_hdl_t grp, entry_handle_t *handle, int priority) {
  MatchErrorCode rc;
  MatchTableIndirectWS *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect_ws(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  return table->add_entry_ws(match_key, grp, handle, priority);
}

MatchErrorCode
Context::mt_indirect_ws_modify_entry(const std::string &table_name,
                                     entry_handle_t handle,
                                     grp_hdl_t grp) {
  MatchErrorCode rc;
  MatchTableIndirectWS *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect_ws(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  return table->modify_entry_ws(handle, grp);
}

MatchErrorCode
Context::mt_indirect_ws_set_default_group(const std::string &table_name,
                                          grp_hdl_t grp) {
  MatchErrorCode rc;
  MatchTableIndirectWS *table;
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  if ((rc = get_mt_indirect_ws(table_name, &table)) != MatchErrorCode::SUCCESS)
    return rc;
  return table->set_default_group(grp);
}

MatchErrorCode
Context::mt_read_counters(const std::string &table_name,
                          entry_handle_t handle,
                          MatchTableAbstract::counter_value_t *bytes,
                          MatchTableAbstract::counter_value_t *packets) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  MatchTableAbstract *abstract_table =
    p4objects_rt->get_abstract_match_table(table_name);
  assert(abstract_table);
  return abstract_table->query_counters(handle, bytes, packets);
}

MatchErrorCode
Context::mt_reset_counters(const std::string &table_name) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  MatchTableAbstract *abstract_table =
    p4objects_rt->get_abstract_match_table(table_name);
  assert(abstract_table);
  return abstract_table->reset_counters();
}

MatchErrorCode
Context::mt_write_counters(const std::string &table_name,
                           entry_handle_t handle,
                           MatchTableAbstract::counter_value_t bytes,
                           MatchTableAbstract::counter_value_t packets) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  MatchTableAbstract *abstract_table =
    p4objects_rt->get_abstract_match_table(table_name);
  assert(abstract_table);
  return abstract_table->write_counters(handle, bytes, packets);
}

MatchErrorCode
Context::mt_set_meter_rates(const std::string &table_name,
                            entry_handle_t handle,
                            const std::vector<Meter::rate_config_t> &configs) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  MatchTableAbstract *abstract_table =
    p4objects_rt->get_abstract_match_table(table_name);
  assert(abstract_table);
  return abstract_table->set_meter_rates(handle, configs);
}

Counter::CounterErrorCode
Context::read_counters(const std::string &counter_name,
                       size_t index,
                       MatchTableAbstract::counter_value_t *bytes,
                       MatchTableAbstract::counter_value_t *packets) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  CounterArray *counter_array = p4objects_rt->get_counter_array(counter_name);
  assert(counter_array);
  return (*counter_array)[index].query_counter(bytes, packets);
}

Counter::CounterErrorCode
Context::reset_counters(const std::string &counter_name) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  CounterArray *counter_array = p4objects_rt->get_counter_array(counter_name);
  assert(counter_array);
  return counter_array->reset_counters();
}

Counter::CounterErrorCode
Context::write_counters(const std::string &counter_name,
                        size_t index,
                        MatchTableAbstract::counter_value_t bytes,
                        MatchTableAbstract::counter_value_t packets) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  CounterArray *counter_array = p4objects_rt->get_counter_array(counter_name);
  assert(counter_array);
  return (*counter_array)[index].write_counter(bytes, packets);
}

Context::MeterErrorCode
Context::meter_array_set_rates(
    const std::string &meter_name,
    const std::vector<Meter::rate_config_t> &configs) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  MeterArray *meter_array = p4objects_rt->get_meter_array(meter_name);
  assert(meter_array);
  return meter_array->set_rates(configs);
}

Context::MeterErrorCode
Context::meter_set_rates(
    const std::string &meter_name, size_t idx,
    const std::vector<Meter::rate_config_t> &configs) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  MeterArray *meter_array = p4objects_rt->get_meter_array(meter_name);
  assert(meter_array);
  return meter_array->get_meter(idx).set_rates(configs);
}

Context::RegisterErrorCode
Context::register_read(const std::string &register_name,
                       const size_t idx, Data *value) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  RegisterArray *register_array =
    p4objects_rt->get_register_array(register_name);
  if (!register_array) return Register::ERROR;
  if (idx >= register_array->size()) return Register::INVALID_INDEX;
  auto register_lock = register_array->unique_lock();
  value->set((*register_array)[idx]);
  return Register::SUCCESS;
}

Context::RegisterErrorCode
Context::register_write(const std::string &register_name,
                        const size_t idx, Data value) {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  RegisterArray *register_array =
    p4objects_rt->get_register_array(register_name);
  if (!register_array) return Register::ERROR;
  if (idx >= register_array->size()) return Register::INVALID_INDEX;
  auto register_lock = register_array->unique_lock();
  (*register_array)[idx].set(std::move(value));
  return Register::SUCCESS;
}

MatchErrorCode
Context::dump_table(const std::string& table_name,
                    std::ostream *stream) const {
  boost::shared_lock<boost::shared_mutex> lock(request_mutex);
  MatchTableAbstract *abstract_table =
    p4objects_rt->get_abstract_match_table(table_name);
  assert(abstract_table);
  abstract_table->dump(stream);
  return MatchErrorCode::SUCCESS;
}

// ---------- End runtime interfaces ----------

LearnEngine *
Context::get_learn_engine() {
  return p4objects->get_learn_engine();
}

AgeingMonitor *
Context::get_ageing_monitor() {
  return p4objects->get_ageing_monitor();
}

PHVFactory &
Context::get_phv_factory() {
  return p4objects->get_phv_factory();
}

void
Context::set_notifications_transport(
    std::shared_ptr<TransportIface> transport) {
  notifications_transport = transport;
}

void
Context::set_device_id(int dev_id) {
  device_id = dev_id;
}

void
Context::set_cxt_id(int id) {
  cxt_id = id;
}

void
Context::set_force_arith(bool v) {
  force_arith = v;
}

int
Context::init_objects(std::istream *is,
                      const std::set<header_field_pair> &required_fields,
                      const std::set<header_field_pair> &arith_fields) {
  // initally p4objects_rt == p4objects, so this works
  int status = p4objects_rt->init_objects(is, device_id, cxt_id,
                                          notifications_transport,
                                          required_fields, arith_fields);
  if (status) return status;
  if (force_arith)
    get_phv_factory().enable_all_arith();
  return 0;
}

Context::ErrorCode
Context::load_new_config(
    std::istream *is,
    const std::set<header_field_pair> &required_fields,
    const std::set<header_field_pair> &arith_fields) {
  boost::unique_lock<boost::shared_mutex> lock(request_mutex);
  // check that there is no ongoing config swap
  if (p4objects != p4objects_rt) return ErrorCode::ONGOING_SWAP;
  p4objects_rt = std::make_shared<P4Objects>();
  init_objects(is, required_fields, arith_fields);
  return ErrorCode::SUCCESS;
}

Context::ErrorCode
Context::swap_configs() {
  boost::unique_lock<boost::shared_mutex> lock(request_mutex);
  // no ongoing swap
  if (p4objects == p4objects_rt) return ErrorCode::NO_ONGOING_SWAP;
  swap_ordered = true;
  return ErrorCode::SUCCESS;
}

Context::ErrorCode
Context::reset_state() {
  boost::unique_lock<boost::shared_mutex> lock(request_mutex);
  p4objects_rt->reset_state();
  return ErrorCode::SUCCESS;
}

int
Context::do_swap() {
  if (!swap_ordered) return 1;
  boost::unique_lock<boost::shared_mutex> lock(request_mutex);
  p4objects = p4objects_rt;
  swap_ordered = false;
  return 0;
}

}  // namespace bm
