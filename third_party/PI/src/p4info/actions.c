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

#include "PI/p4info/actions.h"
#include "PI/int/pi_int.h"
#include "actions_int.h"
#include "p4info/p4info_struct.h"

#include <cJSON/cJSON.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define INLINE_PARAMS 8

typedef struct {
  char *name;
  pi_p4_id_t param_id;
  size_t bitwidth;
  char byte0_mask;
  size_t offset;
} _action_param_data_t;

typedef struct _action_data_s {
  p4info_common_t common;
  char *name;
  pi_p4_id_t action_id;
  size_t num_params;
  union {
    pi_p4_id_t direct[INLINE_PARAMS];
    pi_p4_id_t *indirect;
  } param_ids;
  union {
    _action_param_data_t direct[INLINE_PARAMS];
    _action_param_data_t *indirect;
  } param_data;
  size_t action_data_size;
  size_t params_added;
} _action_data_t;

static _action_data_t *get_action(const pi_p4info_t *p4info,
                                  pi_p4_id_t action_id) {
  assert(PI_GET_TYPE_ID(action_id) == PI_ACTION_ID);
  return p4info_get_at(p4info, action_id);
}

static pi_p4_id_t *get_param_ids(_action_data_t *action) {
  return (action->num_params <= INLINE_PARAMS) ? action->param_ids.direct
                                               : action->param_ids.indirect;
}

static _action_param_data_t *get_param_data(_action_data_t *action) {
  return (action->num_params <= INLINE_PARAMS) ? action->param_data.direct
                                               : action->param_data.indirect;
}

static _action_param_data_t *get_param_data_at(_action_data_t *action,
                                               pi_p4_id_t param_id) {
  _action_param_data_t *param_data = get_param_data(action);
  for (size_t i = 0; i < action->num_params; i++) {
    if (param_data[i].param_id == param_id) return &param_data[i];
  }
  return NULL;
}

static pi_p4_id_t get_param_id(_action_data_t *action, const char *name) {
  pi_p4_id_t *param_ids = get_param_ids(action);
  _action_param_data_t *param_data = get_param_data(action);
  for (size_t i = 0; i < action->num_params; i++) {
    if (!strcmp(name, param_data[i].name)) return param_ids[i];
  }
  return PI_INVALID_ID;
}

static size_t num_actions(const pi_p4info_t *p4info) {
  return num_res(p4info, PI_ACTION_ID);
}

static const char *retrieve_name(const void *data) {
  const _action_data_t *action = (const _action_data_t *)data;
  return action->name;
}

static void free_action_data(void *data) {
  _action_data_t *action = (_action_data_t *)data;
  if (!action->name) return;
  free(action->name);
  _action_param_data_t *params = get_param_data(action);
  for (size_t j = 0; j < action->num_params; j++) {
    _action_param_data_t *param = &params[j];
    if (!param->name) continue;
    free(param->name);
  }
  if (action->num_params > INLINE_PARAMS) {
    assert(action->param_ids.indirect);
    assert(action->param_data.indirect);
    free(action->param_ids.indirect);
    free(action->param_data.indirect);
  }
  p4info_common_destroy(&action->common);
}

void pi_p4info_action_serialize(cJSON *root, const pi_p4info_t *p4info) {
  cJSON *aArray = cJSON_CreateArray();
  const vector_t *actions = p4info->actions->vec;
  for (size_t i = 0; i < vector_size(actions); i++) {
    _action_data_t *action = vector_at(actions, i);
    cJSON *aObject = cJSON_CreateObject();

    cJSON_AddStringToObject(aObject, "name", action->name);
    cJSON_AddNumberToObject(aObject, "id", action->action_id);

    cJSON *pArray = cJSON_CreateArray();
    _action_param_data_t *param_data = get_param_data(action);
    for (size_t j = 0; j < action->num_params; j++) {
      cJSON *p = cJSON_CreateObject();
      cJSON_AddStringToObject(p, "name", param_data[j].name);
      cJSON_AddNumberToObject(p, "id", param_data[j].param_id);
      cJSON_AddNumberToObject(p, "bitwidth", param_data[j].bitwidth);
      cJSON_AddItemToArray(pArray, p);
    }
    cJSON_AddItemToObject(aObject, "params", pArray);

    p4info_common_serialize(aObject, &action->common);

    cJSON_AddItemToArray(aArray, aObject);
  }
  cJSON_AddItemToObject(root, "actions", aArray);
}

void pi_p4info_action_init(pi_p4info_t *p4info, size_t num_actions) {
  p4info_init_res(p4info, PI_ACTION_ID, num_actions, sizeof(_action_data_t),
                  retrieve_name, free_action_data, pi_p4info_action_serialize);
}

void pi_p4info_action_add(pi_p4info_t *p4info, pi_p4_id_t action_id,
                          const char *name, size_t num_params) {
  char *name_copy = strdup(name);
  _action_data_t *action = p4info_add_res(p4info, action_id, name_copy);
  action->name = name_copy;
  action->action_id = action_id;
  action->num_params = num_params;
  if (num_params > INLINE_PARAMS) {
    action->param_ids.indirect = calloc(num_params, sizeof(pi_p4_id_t));
    action->param_data.indirect =
        calloc(num_params, sizeof(_action_param_data_t));
  }
  action->action_data_size = 0;
  action->params_added = 0;
}

static char get_byte0_mask(size_t bitwidth) {
  if (bitwidth % 8 == 0) return 0xff;
  int nbits = bitwidth % 8;
  return ((1 << nbits) - 1);
}

void pi_p4info_action_add_param(pi_p4info_t *p4info, pi_p4_id_t action_id,
                                pi_p4_id_t param_id, const char *name,
                                size_t bitwidth) {
  _action_data_t *action = get_action(p4info, action_id);
  assert(action->params_added < action->num_params);
  _action_param_data_t *param_data =
      &get_param_data(action)[action->params_added];
  param_data->name = strdup(name);
  param_data->param_id = param_id;
  param_data->bitwidth = bitwidth;
  param_data->byte0_mask = get_byte0_mask(bitwidth);
  param_data->offset = action->action_data_size;

  get_param_ids(action)[action->params_added] = param_id;

  action->action_data_size += (bitwidth + 7) / 8;

  action->params_added++;
}

size_t pi_p4info_action_get_num(const pi_p4info_t *p4info) {
  return num_actions(p4info);
}

pi_p4_id_t pi_p4info_action_id_from_name(const pi_p4info_t *p4info,
                                         const char *name) {
  return p4info_name_map_get(&p4info->actions->name_map, name);
}

const char *pi_p4info_action_name_from_id(const pi_p4info_t *p4info,
                                          pi_p4_id_t action_id) {
  _action_data_t *action = get_action(p4info, action_id);
  return action->name;
}

size_t pi_p4info_action_num_params(const pi_p4info_t *p4info,
                                   pi_p4_id_t action_id) {
  _action_data_t *action = get_action(p4info, action_id);
  if (action == NULL)
    return (size_t)(-1);
  else
    return action->num_params;
}

const pi_p4_id_t *pi_p4info_action_get_params(const pi_p4info_t *p4info,
                                              pi_p4_id_t action_id,
                                              size_t *num_params) {
  _action_data_t *action = get_action(p4info, action_id);
  *num_params = action->num_params;
  return get_param_ids(action);
}

pi_p4_id_t pi_p4info_action_param_id_from_name(const pi_p4info_t *p4info,
                                               pi_p4_id_t action_id,
                                               const char *name) {
  _action_data_t *action = get_action(p4info, action_id);
  return get_param_id(action, name);
}

size_t pi_p4info_action_param_index(const pi_p4info_t *p4info,
                                    pi_p4_id_t action_id, pi_p4_id_t param_id) {
  _action_data_t *action = get_action(p4info, action_id);
  pi_p4_id_t *param_ids = get_param_ids(action);
  for (size_t i = 0; i < action->num_params; i++) {
    if (param_ids[i] == param_id) return i;
  }
  return (size_t)-1;
}

const char *pi_p4info_action_param_name_from_id(const pi_p4info_t *p4info,
                                                pi_p4_id_t action_id,
                                                pi_p4_id_t param_id) {
  _action_data_t *action = get_action(p4info, action_id);
  return get_param_data_at(action, param_id)->name;
}

size_t pi_p4info_action_param_bitwidth(const pi_p4info_t *p4info,
                                       pi_p4_id_t action_id,
                                       pi_p4_id_t param_id) {
  _action_data_t *action = get_action(p4info, action_id);
  _action_param_data_t *param = get_param_data_at(action, param_id);
  if (param == NULL)
    return (size_t)(-1);
  else
    return param->bitwidth;
}

char pi_p4info_action_param_byte0_mask(const pi_p4info_t *p4info,
                                       pi_p4_id_t action_id,
                                       pi_p4_id_t param_id) {
  _action_data_t *action = get_action(p4info, action_id);
  return get_param_data_at(action, param_id)->byte0_mask;
}

size_t pi_p4info_action_param_offset(const pi_p4info_t *p4info,
                                     pi_p4_id_t action_id,
                                     pi_p4_id_t param_id) {
  _action_data_t *action = get_action(p4info, action_id);
  _action_param_data_t *param = get_param_data_at(action, param_id);
  if (param == NULL)
    return (size_t)(-1);
  else
    return param->offset;
}

size_t pi_p4info_action_data_size(const pi_p4info_t *p4info,
                                  pi_p4_id_t action_id) {
  _action_data_t *action = get_action(p4info, action_id);
  if (action == NULL)
    return (size_t)(-1);
  else
    return action->action_data_size;
}

pi_p4_id_t pi_p4info_action_begin(const pi_p4info_t *p4info) {
  return pi_p4info_any_begin(p4info, PI_ACTION_ID);
}

pi_p4_id_t pi_p4info_action_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  return pi_p4info_any_next(p4info, id);
}

pi_p4_id_t pi_p4info_action_end(const pi_p4info_t *p4info) {
  return pi_p4info_any_end(p4info, PI_ACTION_ID);
}
