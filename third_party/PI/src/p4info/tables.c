/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
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
 * Antonin Bas
 *
 */

#include "PI/p4info/tables.h"
#include "PI/int/pi_int.h"
#include "fast_id_vector.h"
#include "p4info/p4info_struct.h"
#include "tables_int.h"

#include <cJSON/cJSON.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define INLINE_MATCH_FIELDS 8
#define INLINE_ACTIONS 8

typedef struct {
  pi_p4info_match_field_info_t info;
  size_t offset;
  char byte0_mask;
} _match_field_data_t;

typedef struct _table_data_s {
  p4info_common_t common;
  char *name;
  pi_p4_id_t table_id;
  size_t num_match_fields;
  size_t num_actions;
  union {
    pi_p4_id_t direct[INLINE_MATCH_FIELDS];
    pi_p4_id_t *indirect;
  } match_field_ids;
  union {
    _match_field_data_t direct[INLINE_MATCH_FIELDS];
    _match_field_data_t *indirect;
  } match_field_data;
  union {
    pi_p4_id_t direct[INLINE_ACTIONS];
    pi_p4_id_t *indirect;
  } action_ids;
  union {
    pi_p4info_action_info_t direct[INLINE_ACTIONS];
    pi_p4info_action_info_t *indirect;
  } action_info;
  size_t match_fields_added;
  size_t actions_added;
  // PI_INVALID_ID if no const default action
  pi_p4_id_t const_default_action_id;
  // DEPRECATED
  // Always set to (const_default_action_id == PI_INVALID_ID)
  // e.g. no const action => mutable action params
  bool has_mutable_action_params;
  // PI_INVALID_ID if default
  pi_p4_id_t implementation;
  size_t num_direct_resources;
  id_vector_t direct_resources;
  size_t max_size;
  size_t match_key_size;
  bool is_const;  // immutable table with program-provided entries
  bool supports_idle_timeout;
} _table_data_t;

static _table_data_t *get_table(const pi_p4info_t *p4info,
                                pi_p4_id_t table_id) {
  assert(PI_GET_TYPE_ID(table_id) == PI_TABLE_ID);
  return p4info_get_at(p4info, table_id);
}

static pi_p4_id_t *get_match_field_ids(_table_data_t *table) {
  return (table->num_match_fields <= INLINE_MATCH_FIELDS)
             ? table->match_field_ids.direct
             : table->match_field_ids.indirect;
}

static _match_field_data_t *get_match_field_data(_table_data_t *table) {
  return (table->num_match_fields <= INLINE_MATCH_FIELDS)
             ? table->match_field_data.direct
             : table->match_field_data.indirect;
}

static pi_p4_id_t *get_action_ids(_table_data_t *table) {
  return (table->num_actions <= INLINE_ACTIONS) ? table->action_ids.direct
                                                : table->action_ids.indirect;
}

static pi_p4info_action_info_t *get_action_info(_table_data_t *table) {
  return (table->num_actions <= INLINE_ACTIONS) ? table->action_info.direct
                                                : table->action_info.indirect;
}

static pi_p4_id_t *get_direct_resources(_table_data_t *table) {
  return ID_VECTOR_GET(table->direct_resources);
}

static const char *retrieve_name(const void *data) {
  const _table_data_t *table = (const _table_data_t *)data;
  return table->name;
}

static pi_p4_id_t get_match_field_id(_table_data_t *table, const char *name) {
  pi_p4_id_t *match_field_ids = get_match_field_ids(table);
  _match_field_data_t *match_field_data = get_match_field_data(table);
  for (size_t i = 0; i < table->num_match_fields; i++) {
    if (!strcmp(name, match_field_data[i].info.name)) return match_field_ids[i];
  }
  return PI_INVALID_ID;
}

static const char *get_match_field_name(_table_data_t *table, pi_p4_id_t id) {
  _match_field_data_t *match_field_data = get_match_field_data(table);
  for (size_t i = 0; i < table->num_match_fields; i++) {
    if (match_field_data[i].info.mf_id == id)
      return match_field_data[i].info.name;
  }
  return NULL;
}

static void free_table_data(void *data) {
  _table_data_t *table = (_table_data_t *)data;
  if (!table->name) return;
  free(table->name);
  _match_field_data_t *match_fields = get_match_field_data(table);
  for (size_t j = 0; j < table->num_match_fields; j++) {
    pi_p4info_match_field_info_t *mf_info = &match_fields[j].info;
    if (!mf_info->name) continue;
    free(mf_info->name);
  }
  if (table->num_match_fields > INLINE_MATCH_FIELDS) {
    assert(table->match_field_ids.indirect);
    assert(table->match_field_data.indirect);
    free(table->match_field_ids.indirect);
    free(table->match_field_data.indirect);
  }
  if (table->num_actions > INLINE_ACTIONS) {
    assert(table->action_ids.indirect);
    assert(table->action_info.indirect);
    free(table->action_ids.indirect);
    free(table->action_info.indirect);
  }
  ID_VECTOR_DESTROY(table->direct_resources);
  p4info_common_destroy(&table->common);
}

void pi_p4info_table_serialize(cJSON *root, const pi_p4info_t *p4info) {
  cJSON *tArray = cJSON_CreateArray();
  const vector_t *tables = p4info->tables->vec;
  for (size_t i = 0; i < vector_size(tables); i++) {
    _table_data_t *table = vector_at(tables, i);
    cJSON *tObject = cJSON_CreateObject();

    cJSON_AddStringToObject(tObject, "name", table->name);
    cJSON_AddNumberToObject(tObject, "id", table->table_id);

    cJSON *mfArray = cJSON_CreateArray();
    _match_field_data_t *mf_data = get_match_field_data(table);
    for (size_t j = 0; j < table->num_match_fields; j++) {
      pi_p4info_match_field_info_t *mf_info = &mf_data[j].info;
      cJSON *mf = cJSON_CreateObject();
      cJSON_AddStringToObject(mf, "name", mf_info->name);
      cJSON_AddNumberToObject(mf, "id", mf_info->mf_id);
      cJSON_AddNumberToObject(mf, "bitwidth", mf_info->bitwidth);
      cJSON_AddNumberToObject(mf, "match_type", mf_info->match_type);
      cJSON_AddItemToArray(mfArray, mf);
    }
    cJSON_AddItemToObject(tObject, "match_fields", mfArray);

    cJSON *actionsArray = cJSON_CreateArray();
    for (size_t j = 0; j < table->num_actions; j++) {
      pi_p4info_action_info_t *action_info = &get_action_info(table)[j];
      cJSON *action = cJSON_CreateObject();
      cJSON_AddNumberToObject(action, "id", action_info->id);
      cJSON_AddNumberToObject(action, "scope", action_info->scope);
      cJSON_AddItemToArray(actionsArray, action);
    }
    cJSON_AddItemToObject(tObject, "actions", actionsArray);

    cJSON_AddNumberToObject(tObject, "const_default_action_id",
                            table->const_default_action_id);
    cJSON_AddBoolToObject(tObject, "has_mutable_action_params",
                          table->has_mutable_action_params);

    cJSON_AddNumberToObject(tObject, "implementation", table->implementation);

    cJSON *directresArray = cJSON_CreateArray();
    pi_p4_id_t *direct_res_ids = get_direct_resources(table);
    for (size_t j = 0; j < table->num_direct_resources; j++) {
      cJSON *direct_res = cJSON_CreateNumber(direct_res_ids[j]);
      cJSON_AddItemToArray(directresArray, direct_res);
    }
    cJSON_AddItemToObject(tObject, "direct_resources", directresArray);

    cJSON_AddNumberToObject(tObject, "max_size", table->max_size);

    cJSON_AddBoolToObject(tObject, "is_const", table->is_const);

    cJSON_AddBoolToObject(tObject, "supports_idle_timeout",
                          table->supports_idle_timeout);

    p4info_common_serialize(tObject, &table->common);

    cJSON_AddItemToArray(tArray, tObject);
  }
  cJSON_AddItemToObject(root, "tables", tArray);
}

void pi_p4info_table_init(pi_p4info_t *p4info, size_t num_tables) {
  p4info_init_res(p4info, PI_TABLE_ID, num_tables, sizeof(_table_data_t),
                  retrieve_name, free_table_data, pi_p4info_table_serialize);
}

void pi_p4info_table_add(pi_p4info_t *p4info, pi_p4_id_t table_id,
                         const char *name, size_t num_match_fields,
                         size_t num_actions, size_t max_size, bool is_const,
                         bool supports_idle_timeout) {
  char *name_copy = strdup(name);
  _table_data_t *table = p4info_add_res(p4info, table_id, name_copy);
  table->name = name_copy;
  table->table_id = table_id;
  table->num_match_fields = num_match_fields;
  table->num_actions = num_actions;
  if (num_match_fields > INLINE_MATCH_FIELDS) {
    table->match_field_ids.indirect =
        calloc(num_match_fields, sizeof(pi_p4_id_t));
    table->match_field_data.indirect =
        calloc(num_match_fields, sizeof(_match_field_data_t));
  }
  if (num_actions > INLINE_ACTIONS) {
    table->action_ids.indirect = calloc(num_actions, sizeof(pi_p4_id_t));
    table->action_info.indirect =
        calloc(num_actions, sizeof(pi_p4info_action_info_t));
  }

  table->const_default_action_id = PI_INVALID_ID;
  table->has_mutable_action_params = true;
  table->implementation = PI_INVALID_ID;
  table->num_direct_resources = 0;
  table->match_fields_added = 0;
  table->max_size = max_size;
  table->match_key_size = 0;
  table->is_const = is_const;
  table->supports_idle_timeout = supports_idle_timeout;
}

static char get_byte0_mask(size_t bitwidth) {
  if (bitwidth % 8 == 0) return 0xff;
  int nbits = bitwidth % 8;
  return ((1 << nbits) - 1);
}

void pi_p4info_table_add_match_field(pi_p4info_t *p4info, pi_p4_id_t table_id,
                                     pi_p4_id_t mf_id, const char *name,
                                     pi_p4info_match_type_t match_type,
                                     size_t bitwidth) {
  _table_data_t *table = get_table(p4info, table_id);
  assert(table->match_fields_added < table->num_match_fields);
  _match_field_data_t *mf_data =
      &get_match_field_data(table)[table->match_fields_added];
  pi_p4info_match_field_info_t *mf_info = &mf_data->info;
  assert(!mf_info->name);
  mf_info->name = strdup(name);
  mf_info->mf_id = mf_id;
  mf_info->match_type = match_type;
  mf_info->bitwidth = bitwidth;
  get_match_field_ids(table)[table->match_fields_added] = mf_id;

  mf_data->offset = table->match_key_size;
  mf_data->byte0_mask = get_byte0_mask(bitwidth);

  size_t size =
      get_match_key_size_one_field(mf_info->match_type, mf_info->bitwidth);
  table->match_key_size += size;

  table->match_fields_added++;
}

void pi_p4info_table_add_action(pi_p4info_t *p4info, pi_p4_id_t table_id,
                                pi_p4_id_t action_id,
                                pi_p4info_action_scope_t action_scope) {
  _table_data_t *table = get_table(p4info, table_id);
  assert(table->actions_added < table->num_actions);
  get_action_ids(table)[table->actions_added] = action_id;
  pi_p4info_action_info_t *info = &get_action_info(table)[table->actions_added];
  info->id = action_id;
  info->scope = action_scope;
  table->actions_added++;
}

void pi_p4info_table_set_implementation(pi_p4info_t *p4info,
                                        pi_p4_id_t table_id,
                                        pi_p4_id_t implementation) {
  _table_data_t *table = get_table(p4info, table_id);
  table->implementation = implementation;
}

void pi_p4info_table_set_const_default_action(pi_p4info_t *p4info,
                                              pi_p4_id_t table_id,
                                              pi_p4_id_t default_action_id) {
  _table_data_t *table = get_table(p4info, table_id);
  assert(table->num_actions > 0);
  assert(pi_p4info_table_is_action_of(p4info, table_id, default_action_id));
  table->const_default_action_id = default_action_id;
  table->has_mutable_action_params = false;
}

void pi_p4info_table_add_direct_resource(pi_p4info_t *p4info,
                                         pi_p4_id_t table_id,
                                         pi_p4_id_t direct_res_id) {
  _table_data_t *table = get_table(p4info, table_id);
  ID_VECTOR_PUSH_BACK(table->direct_resources, direct_res_id);
  table->num_direct_resources++;
}

pi_p4_id_t pi_p4info_table_id_from_name(const pi_p4info_t *p4info,
                                        const char *name) {
  return p4info_name_map_get(&p4info->tables->name_map, name);
}

const char *pi_p4info_table_name_from_id(const pi_p4info_t *p4info,
                                         pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->name;
}

size_t pi_p4info_table_num_match_fields(const pi_p4info_t *p4info,
                                        pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->num_match_fields;
}

const pi_p4_id_t *pi_p4info_table_get_match_fields(const pi_p4info_t *p4info,
                                                   pi_p4_id_t table_id,
                                                   size_t *num_match_fields) {
  _table_data_t *table = get_table(p4info, table_id);
  *num_match_fields = table->num_match_fields;
  return get_match_field_ids(table);
}

bool pi_p4info_table_is_match_field_of(const pi_p4info_t *p4info,
                                       pi_p4_id_t table_id, pi_p4_id_t mf_id) {
  _table_data_t *table = get_table(p4info, table_id);
  pi_p4_id_t *ids = get_match_field_ids(table);
  for (size_t i = 0; i < table->num_match_fields; i++)
    if (ids[i] == mf_id) return true;
  return false;
}

pi_p4_id_t pi_p4info_table_match_field_id_from_name(const pi_p4info_t *p4info,
                                                    pi_p4_id_t table_id,
                                                    const char *name) {
  _table_data_t *table = get_table(p4info, table_id);
  return get_match_field_id(table, name);
}

const char *pi_p4info_table_match_field_name_from_id(const pi_p4info_t *p4info,
                                                     pi_p4_id_t table_id,
                                                     pi_p4_id_t mf_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return get_match_field_name(table, mf_id);
}

size_t pi_p4info_table_match_field_index(const pi_p4info_t *p4info,
                                         pi_p4_id_t table_id,
                                         pi_p4_id_t mf_id) {
  _table_data_t *table = get_table(p4info, table_id);
  pi_p4_id_t *ids = get_match_field_ids(table);
  for (size_t i = 0; i < table->num_match_fields; i++)
    if (ids[i] == mf_id) return i;
  return (size_t)-1;
}

size_t pi_p4info_table_match_field_offset(const pi_p4info_t *p4info,
                                          pi_p4_id_t table_id,
                                          pi_p4_id_t mf_id) {
  size_t index = pi_p4info_table_match_field_index(p4info, table_id, mf_id);
  _table_data_t *table = get_table(p4info, table_id);
  _match_field_data_t *data = &get_match_field_data(table)[index];
  return data->offset;
}

size_t pi_p4info_table_match_field_bitwidth(const pi_p4info_t *p4info,
                                            pi_p4_id_t table_id,
                                            pi_p4_id_t mf_id) {
  size_t invalid = (size_t)-1;
  size_t index = pi_p4info_table_match_field_index(p4info, table_id, mf_id);
  if (invalid == index) return invalid;
  _table_data_t *table = get_table(p4info, table_id);
  _match_field_data_t *data = &get_match_field_data(table)[index];
  return data->info.bitwidth;
}

size_t pi_p4info_table_match_field_byte0_mask(const pi_p4info_t *p4info,
                                              pi_p4_id_t table_id,
                                              pi_p4_id_t mf_id) {
  size_t index = pi_p4info_table_match_field_index(p4info, table_id, mf_id);
  _table_data_t *table = get_table(p4info, table_id);
  _match_field_data_t *data = &get_match_field_data(table)[index];
  return data->byte0_mask;
}

size_t pi_p4info_table_match_key_size(const pi_p4info_t *p4info,
                                      pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->match_key_size;
}

const pi_p4info_match_field_info_t *pi_p4info_table_match_field_info(
    const pi_p4info_t *p4info, pi_p4_id_t table_id, size_t index) {
  _table_data_t *table = get_table(p4info, table_id);
  _match_field_data_t *data = &get_match_field_data(table)[index];
  return &data->info;
}

size_t pi_p4info_table_num_actions(const pi_p4info_t *p4info,
                                   pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->num_actions;
}

bool pi_p4info_table_is_action_of(const pi_p4info_t *p4info,
                                  pi_p4_id_t table_id, pi_p4_id_t action_id) {
  _table_data_t *table = get_table(p4info, table_id);
  pi_p4_id_t *ids = get_action_ids(table);
  for (size_t i = 0; i < table->num_actions; i++)
    if (ids[i] == action_id) return true;
  return false;
}

const pi_p4_id_t *pi_p4info_table_get_actions(const pi_p4info_t *p4info,
                                              pi_p4_id_t table_id,
                                              size_t *num_actions) {
  _table_data_t *table = get_table(p4info, table_id);
  *num_actions = table->num_actions;
  return get_action_ids(table);
}

const pi_p4info_action_info_t *pi_p4info_table_get_action_info(
    const pi_p4info_t *p4info, pi_p4_id_t table_id, pi_p4_id_t action_id) {
  _table_data_t *table = get_table(p4info, table_id);
  pi_p4info_action_info_t *info = get_action_info(table);
  for (size_t i = 0; i < table->num_actions; i++)
    if (info[i].id == action_id) return &info[i];
  return NULL;
}

bool pi_p4info_table_has_const_default_action(const pi_p4info_t *p4info,
                                              pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return (table->const_default_action_id != PI_INVALID_ID);
}

pi_p4_id_t pi_p4info_table_get_const_default_action(
    const pi_p4info_t *p4info, pi_p4_id_t table_id,
    bool *has_mutable_action_params) {
  _table_data_t *table = get_table(p4info, table_id);
  *has_mutable_action_params = table->has_mutable_action_params;
  return table->const_default_action_id;
}

pi_p4_id_t pi_p4info_table_get_implementation(const pi_p4info_t *p4info,
                                              pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->implementation;
}

bool pi_p4info_table_is_direct_resource_of(const pi_p4info_t *p4info,
                                           pi_p4_id_t table_id,
                                           pi_p4_id_t direct_res_id) {
  _table_data_t *table = get_table(p4info, table_id);
  pi_p4_id_t *ids = get_direct_resources(table);
  for (size_t i = 0; i < table->num_direct_resources; i++)
    if (ids[i] == direct_res_id) return true;
  return false;
}

size_t pi_p4info_table_num_direct_resources(const pi_p4info_t *p4info,
                                            pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->num_direct_resources;
}

const pi_p4_id_t *pi_p4info_table_get_direct_resources(
    const pi_p4info_t *p4info, pi_p4_id_t table_id,
    size_t *num_direct_resources) {
  _table_data_t *table = get_table(p4info, table_id);
  *num_direct_resources = table->num_direct_resources;
  return get_direct_resources(table);
}

size_t pi_p4info_table_max_size(const pi_p4info_t *p4info,
                                pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->max_size;
}

bool pi_p4info_table_is_const(const pi_p4info_t *p4info, pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->is_const;
}

bool pi_p4info_table_supports_idle_timeout(const pi_p4info_t *p4info,
                                           pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->supports_idle_timeout;
}

pi_p4_id_t pi_p4info_table_begin(const pi_p4info_t *p4info) {
  return pi_p4info_any_begin(p4info, PI_TABLE_ID);
}

pi_p4_id_t pi_p4info_table_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  return pi_p4info_any_next(p4info, id);
}

pi_p4_id_t pi_p4info_table_end(const pi_p4info_t *p4info) {
  return pi_p4info_any_end(p4info, PI_TABLE_ID);
}
