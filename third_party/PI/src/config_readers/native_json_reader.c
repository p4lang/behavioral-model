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

#include "PI/int/pi_int.h"
#include "PI/pi_base.h"
#include "p4info_int.h"

#include <cJSON/cJSON.h>

#include <assert.h>

static void import_annotations(cJSON *object, pi_p4info_t *p4info,
                               pi_p4_id_t id) {
  cJSON *annotations = cJSON_GetObjectItem(object, "annotations");
  if (!annotations) return;
  cJSON *annotation;
  cJSON_ArrayForEach(annotation, annotations) {
    pi_p4info_add_annotation(p4info, id, annotation->valuestring);
  }
}

static void import_aliases(cJSON *object, pi_p4info_t *p4info, pi_p4_id_t id) {
  cJSON *aliases = cJSON_GetObjectItem(object, "aliases");
  if (!aliases) return;
  cJSON *alias;
  cJSON_ArrayForEach(alias, aliases) {
    pi_p4info_add_alias(p4info, id, alias->valuestring);
  }
}

static void import_common(cJSON *object, pi_p4info_t *p4info, pi_p4_id_t id) {
  import_annotations(object, p4info, id);
  import_aliases(object, p4info, id);
}

static pi_status_t read_actions(cJSON *root, pi_p4info_t *p4info) {
  assert(root);
  cJSON *actions = cJSON_GetObjectItem(root, "actions");
  if (!actions) return PI_STATUS_CONFIG_READER_ERROR;
  size_t num_actions = cJSON_GetArraySize(actions);
  pi_p4info_action_init(p4info, num_actions);

  cJSON *action;
  cJSON_ArrayForEach(action, actions) {
    const cJSON *item;
    item = cJSON_GetObjectItem(action, "name");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *name = item->valuestring;
    item = cJSON_GetObjectItem(action, "id");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    pi_p4_id_t pi_id = item->valueint;
    cJSON *params = cJSON_GetObjectItem(action, "params");
    if (!params) return PI_STATUS_CONFIG_READER_ERROR;
    size_t num_params = cJSON_GetArraySize(params);

    pi_p4info_action_add(p4info, pi_id, name, num_params);

    cJSON *param;
    cJSON_ArrayForEach(param, params) {
      item = cJSON_GetObjectItem(param, "name");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      const char *param_name = item->valuestring;

      item = cJSON_GetObjectItem(param, "id");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      pi_p4_id_t id = item->valueint;

      item = cJSON_GetObjectItem(param, "bitwidth");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      int param_bitwidth = item->valueint;

      pi_p4info_action_add_param(p4info, pi_id, id, param_name, param_bitwidth);
    }

    import_common(action, p4info, pi_id);
  }

  return PI_STATUS_SUCCESS;
}

static pi_status_t read_tables(cJSON *root, pi_p4info_t *p4info) {
  assert(root);
  cJSON *tables = cJSON_GetObjectItem(root, "tables");
  if (!tables) return PI_STATUS_CONFIG_READER_ERROR;
  size_t num_tables = cJSON_GetArraySize(tables);
  pi_p4info_table_init(p4info, num_tables);

  cJSON *table;
  cJSON_ArrayForEach(table, tables) {
    const cJSON *item;
    item = cJSON_GetObjectItem(table, "name");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *name = item->valuestring;
    item = cJSON_GetObjectItem(table, "id");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    pi_p4_id_t pi_id = item->valueint;
    cJSON *match_fields = cJSON_GetObjectItem(table, "match_fields");
    if (!match_fields) return PI_STATUS_CONFIG_READER_ERROR;
    size_t num_match_fields = cJSON_GetArraySize(match_fields);
    cJSON *actions = cJSON_GetObjectItem(table, "actions");
    if (!actions) return PI_STATUS_CONFIG_READER_ERROR;
    size_t num_actions = cJSON_GetArraySize(actions);
    item = cJSON_GetObjectItem(table, "max_size");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    size_t max_size = item->valueint;
    item = cJSON_GetObjectItem(table, "is_const");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    if (item->type != cJSON_True && item->type != cJSON_False)
      return PI_STATUS_CONFIG_READER_ERROR;
    bool is_const = (item->type == cJSON_True);
    item = cJSON_GetObjectItem(table, "supports_idle_timeout");
    bool supports_idle_timeout = false;
    if (item) {
      if (item->type != cJSON_True && item->type != cJSON_False)
        return PI_STATUS_CONFIG_READER_ERROR;
      supports_idle_timeout = (item->type == cJSON_True);
    }

    pi_p4info_table_add(p4info, pi_id, name, num_match_fields, num_actions,
                        max_size, is_const, supports_idle_timeout);

    import_common(table, p4info, pi_id);

    cJSON *match_field;
    cJSON_ArrayForEach(match_field, match_fields) {
      item = cJSON_GetObjectItem(match_field, "name");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      const char *fname = item->valuestring;

      item = cJSON_GetObjectItem(match_field, "id");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      pi_p4_id_t id = item->valueint;

      item = cJSON_GetObjectItem(match_field, "bitwidth");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      size_t bitwidth = item->valueint;

      item = cJSON_GetObjectItem(match_field, "match_type");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      pi_p4info_match_type_t match_type = item->valueint;

      pi_p4info_table_add_match_field(p4info, pi_id, id, fname, match_type,
                                      bitwidth);
    }

    cJSON *action;
    cJSON_ArrayForEach(action, actions) {
      item = cJSON_GetObjectItem(action, "id");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      pi_p4_id_t id = item->valueint;
      item = cJSON_GetObjectItem(action, "scope");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      pi_p4info_action_scope_t scope = (pi_p4info_action_scope_t)item->valueint;
      pi_p4info_table_add_action(p4info, pi_id, id, scope);
    }

    item = cJSON_GetObjectItem(table, "const_default_action_id");
    if (item && item->valueint != PI_INVALID_ID) {
      pi_p4_id_t const_default_action_id = item->valueint;
      pi_p4info_table_set_const_default_action(p4info, pi_id,
                                               const_default_action_id);
    }

    item = cJSON_GetObjectItem(table, "implementation");
    if (item && item->valueint != PI_INVALID_ID) {
      pi_p4info_table_set_implementation(p4info, pi_id, item->valueint);
    }

    item = cJSON_GetObjectItem(table, "direct_resources");
    if (item) {
      cJSON *direct_res;
      cJSON_ArrayForEach(direct_res, item) {
        pi_p4_id_t id = direct_res->valueint;
        pi_p4info_table_add_direct_resource(p4info, pi_id, id);
      }
    }
  }

  return PI_STATUS_SUCCESS;
}

static pi_status_t read_act_profs(cJSON *root, pi_p4info_t *p4info) {
  assert(root);
  cJSON *act_profs = cJSON_GetObjectItem(root, "act_profs");
  if (!act_profs) return PI_STATUS_CONFIG_READER_ERROR;
  size_t num_act_profs = cJSON_GetArraySize(act_profs);
  pi_p4info_act_prof_init(p4info, num_act_profs);

  cJSON *act_prof;
  cJSON_ArrayForEach(act_prof, act_profs) {
    const cJSON *item;
    item = cJSON_GetObjectItem(act_prof, "name");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *name = item->valuestring;
    item = cJSON_GetObjectItem(act_prof, "id");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    pi_p4_id_t pi_id = item->valueint;
    item = cJSON_GetObjectItem(act_prof, "with_selector");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    assert(item->type == cJSON_True || item->type == cJSON_False);
    bool with_selector = (item->type == cJSON_True);
    item = cJSON_GetObjectItem(act_prof, "max_size");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    size_t max_size = item->valueint;

    pi_p4info_act_prof_add(p4info, pi_id, name, with_selector, max_size);

    import_common(act_prof, p4info, pi_id);

    item = cJSON_GetObjectItem(act_prof, "tables");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    cJSON *table;
    cJSON_ArrayForEach(table, item) {
      pi_p4_id_t id = table->valueint;
      pi_p4info_act_prof_add_table(p4info, pi_id, id);
    }

    item = cJSON_GetObjectItem(act_prof, "max_group_size");
    if (item)
      pi_p4info_act_prof_set_max_grp_size(p4info, pi_id, item->valueint);
  }

  return PI_STATUS_SUCCESS;
}

static pi_status_t read_counters_generic(cJSON *counters, pi_p4info_t *p4info) {
  cJSON *counter;
  cJSON_ArrayForEach(counter, counters) {
    const cJSON *item;
    item = cJSON_GetObjectItem(counter, "name");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *name = item->valuestring;
    item = cJSON_GetObjectItem(counter, "id");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    pi_p4_id_t pi_id = item->valueint;
    item = cJSON_GetObjectItem(counter, "direct_table");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    pi_p4_id_t direct_tid = item->valueint;
    item = cJSON_GetObjectItem(counter, "counter_unit");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    pi_p4info_counter_unit_t counter_unit = item->valueint;
    item = cJSON_GetObjectItem(counter, "size");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    size_t size = item->valueint;

    if (direct_tid != PI_INVALID_ID) {
      pi_p4info_direct_counter_add(p4info, pi_id, name, counter_unit, size,
                                   direct_tid);
    } else {
      pi_p4info_counter_add(p4info, pi_id, name, counter_unit, size);
    }

    import_common(counter, p4info, pi_id);
  }
  return PI_STATUS_SUCCESS;
}

static pi_status_t read_counters(cJSON *root, pi_p4info_t *p4info) {
  assert(root);
  cJSON *counters = cJSON_GetObjectItem(root, "counters");
  if (!counters) return PI_STATUS_CONFIG_READER_ERROR;
  size_t num_counters = cJSON_GetArraySize(counters);
  pi_p4info_counter_init(p4info, num_counters);
  return read_counters_generic(counters, p4info);
}

static pi_status_t read_direct_counters(cJSON *root, pi_p4info_t *p4info) {
  assert(root);
  cJSON *counters = cJSON_GetObjectItem(root, "direct_counters");
  if (!counters) return PI_STATUS_CONFIG_READER_ERROR;
  size_t num_counters = cJSON_GetArraySize(counters);
  pi_p4info_direct_counter_init(p4info, num_counters);
  return read_counters_generic(counters, p4info);
}

static pi_status_t read_meters_generic(cJSON *meters, pi_p4info_t *p4info) {
  cJSON *meter;
  cJSON_ArrayForEach(meter, meters) {
    const cJSON *item;
    item = cJSON_GetObjectItem(meter, "name");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *name = item->valuestring;
    item = cJSON_GetObjectItem(meter, "id");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    pi_p4_id_t pi_id = item->valueint;
    item = cJSON_GetObjectItem(meter, "direct_table");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    pi_p4_id_t direct_tid = item->valueint;
    item = cJSON_GetObjectItem(meter, "meter_unit");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    pi_p4info_meter_unit_t meter_unit = item->valueint;
    item = cJSON_GetObjectItem(meter, "meter_type");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    pi_p4info_meter_type_t meter_type = item->valueint;
    item = cJSON_GetObjectItem(meter, "size");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    size_t size = item->valueint;

    if (direct_tid != PI_INVALID_ID) {
      pi_p4info_direct_meter_add(p4info, pi_id, name, meter_unit, meter_type,
                                 size, direct_tid);
    } else {
      pi_p4info_meter_add(p4info, pi_id, name, meter_unit, meter_type, size);
    }

    import_common(meter, p4info, pi_id);
  }

  return PI_STATUS_SUCCESS;
}

static pi_status_t read_meters(cJSON *root, pi_p4info_t *p4info) {
  assert(root);
  cJSON *meters = cJSON_GetObjectItem(root, "meters");
  if (!meters) return PI_STATUS_CONFIG_READER_ERROR;
  size_t num_meters = cJSON_GetArraySize(meters);
  pi_p4info_meter_init(p4info, num_meters);
  return read_meters_generic(meters, p4info);
}

static pi_status_t read_direct_meters(cJSON *root, pi_p4info_t *p4info) {
  assert(root);
  cJSON *meters = cJSON_GetObjectItem(root, "direct_meters");
  if (!meters) return PI_STATUS_CONFIG_READER_ERROR;
  size_t num_meters = cJSON_GetArraySize(meters);
  pi_p4info_direct_meter_init(p4info, num_meters);
  return read_meters_generic(meters, p4info);
}

static pi_status_t read_digests(cJSON *root, pi_p4info_t *p4info) {
  assert(root);
  cJSON *digests = cJSON_GetObjectItem(root, "digests");
  if (!digests) return PI_STATUS_CONFIG_READER_ERROR;
  size_t num_digests = cJSON_GetArraySize(digests);
  pi_p4info_digest_init(p4info, num_digests);

  cJSON *digest;
  cJSON_ArrayForEach(digest, digests) {
    const cJSON *item;
    item = cJSON_GetObjectItem(digest, "name");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *name = item->valuestring;
    item = cJSON_GetObjectItem(digest, "id");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    pi_p4_id_t pi_id = item->valueint;

    cJSON *fields = cJSON_GetObjectItem(digest, "fields");
    if (!fields) return PI_STATUS_CONFIG_READER_ERROR;
    pi_p4info_digest_add(p4info, pi_id, name, cJSON_GetArraySize(fields));
    import_common(digest, p4info, pi_id);

    cJSON *field;
    cJSON_ArrayForEach(field, fields) {
      item = cJSON_GetObjectItem(field, "name");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      const char *f_name = item->valuestring;
      item = cJSON_GetObjectItem(field, "bitwidth");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      pi_p4_id_t f_bitwidth = item->valueint;
      pi_p4info_digest_add_field(p4info, pi_id, f_name, f_bitwidth);
    }
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t pi_native_json_reader(const char *config, pi_p4info_t *p4info) {
  cJSON *root = cJSON_Parse(config);
  if (!root) return PI_STATUS_CONFIG_READER_ERROR;

  pi_status_t status;

  if ((status = read_actions(root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  if ((status = read_tables(root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  if ((status = read_act_profs(root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  if ((status = read_counters(root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  if ((status = read_direct_counters(root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  if ((status = read_meters(root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  if ((status = read_direct_meters(root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  if ((status = read_digests(root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  cJSON_Delete(root);

  return PI_STATUS_SUCCESS;
}
