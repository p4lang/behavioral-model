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

#include "PI/int/pi_int.h"
#include "PI/pi_base.h"
#include "p4info_int.h"
#include "utils/logging.h"
#include "vector.h"

#include <cJSON/cJSON.h>
#include <uthash.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define MAX_IDS_IN_ANNOTATION 16

static const int required_major_version = 2;
static const int min_minor_version = 0;

typedef struct {
  pi_p4_id_t id;
  UT_hash_handle hh;
} id_hash_t;

typedef struct {
  char *name;
  size_t bitwidth;
  UT_hash_handle hh;
} field_bitwidth_t;

typedef struct {
  // Set to keep track of which ids have already been allocated
  id_hash_t *allocated_ids;
  // Set to keep track of which ids have already been reserved
  id_hash_t *reserved_ids;
  // Hash to map field names to integer bitwidths; used when adding match fields
  // to tables in p4info
  field_bitwidth_t *fields_bitwidth;
} reader_state_t;

static void init_reader_state(reader_state_t *state) {
  state->allocated_ids = NULL;
  state->reserved_ids = NULL;
  state->fields_bitwidth = NULL;
}

static void destroy_reader_state(reader_state_t *state) {
  // deletion-safe iterations
  id_hash_t *id_hash, *id_hash_tmp;
  HASH_ITER(hh, state->allocated_ids, id_hash, id_hash_tmp) {
    HASH_DEL(state->allocated_ids, id_hash);
    free(id_hash);
  }
  HASH_ITER(hh, state->reserved_ids, id_hash, id_hash_tmp) {
    HASH_DEL(state->reserved_ids, id_hash);
    free(id_hash);
  }
  field_bitwidth_t *f_bw, *f_bw_tmp;
  HASH_ITER(hh, state->fields_bitwidth, f_bw, f_bw_tmp) {
    free(f_bw->name);
    HASH_DEL(state->fields_bitwidth, f_bw);
    free(f_bw);
  }
}

static void parse_ids(const char *str, const char *name, pi_p4_id_t *ids,
                      size_t *num_ids) {
  (void)name;
  char *str_copy = strdup(str);
  char *str_pos = str_copy;
  char *saveptr;
  const char *delim = " \t";
  char *token = NULL;
  *num_ids = 0;
  while ((token = strtok_r(str_pos, delim, &saveptr))) {
    if (*num_ids > MAX_IDS_IN_ANNOTATION) {
      PI_LOG_ERROR("Too many ids for object '%s'\n", name);
      exit(1);
    }
    char *endptr = NULL;
    ids[*num_ids] = strtol(token, &endptr, 0);
    (*num_ids)++;
    if (*endptr != '\0') {
      PI_LOG_ERROR("Invalid 'id' annotation for object '%s'\n", name);
      exit(1);
    }
    str_pos = NULL;
  }
  free(str_copy);
}

// iterates over annotations looking for the right one ("id"); if does not
// exist, return PI_INVALID_ID
static void find_annotation_id(cJSON *object, pi_p4_id_t *ids,
                               size_t *num_ids) {
  *num_ids = 0;
  cJSON *pragmas = cJSON_GetObjectItem(object, "pragmas");
  if (!pragmas) return;
  const cJSON *item = cJSON_GetObjectItem(object, "name");
  const char *name = item->valuestring;
  cJSON *pragma;
  cJSON_ArrayForEach(pragma, pragmas) {
    if (!strncmp(pragma->valuestring, "id ", 3)) {
      const char *id_str = strchr(pragma->valuestring, ' ');
      parse_ids(id_str, name, ids, num_ids);
      return;
    }
  }
}

static bool is_id_reserved(reader_state_t *state, pi_p4_id_t id) {
  id_hash_t *id_hash;
  HASH_FIND(hh, state->reserved_ids, &id, sizeof(id), id_hash);
  return (id_hash != NULL);
}

static void reserve_id(reader_state_t *state, pi_p4_id_t id) {
  id_hash_t *id_hash;
  id_hash = malloc(sizeof(*id_hash));
  id_hash->id = id;
  HASH_ADD(hh, state->reserved_ids, id, sizeof(id), id_hash);
}

static bool is_id_allocated(reader_state_t *state, pi_p4_id_t id) {
  id_hash_t *id_hash;
  HASH_FIND(hh, state->allocated_ids, &id, sizeof(id), id_hash);
  return (id_hash != NULL);
}

static void allocate_id(reader_state_t *state, pi_p4_id_t id) {
  id_hash_t *id_hash;
  id_hash = malloc(sizeof(*id_hash));
  id_hash->id = id;
  HASH_ADD(hh, state->allocated_ids, id, sizeof(id), id_hash);
}

static void pre_reserve_ids(reader_state_t *state, pi_res_type_id_t type_id,
                            cJSON *objects) {
  pi_p4_id_t ids[MAX_IDS_IN_ANNOTATION];
  size_t num_ids = 0;
  bool found_id = false;
  cJSON *object;
  cJSON_ArrayForEach(object, objects) {
    find_annotation_id(object, ids, &num_ids);
    if (num_ids == 0) continue;
    const cJSON *item = cJSON_GetObjectItem(object, "name");
    const char *name = item->valuestring;
    (void)name;
    for (size_t i = 0; i < num_ids; i++) {
      pi_p4_id_t id = ids[i];
      pi_p4_id_t full_id = (type_id << 24) | id;
      if (id > 0xffff) {
        PI_LOG_ERROR("User specified ids cannot exceed 0xffff.\n");
        exit(1);
      }
      if (!is_id_reserved(state, full_id)) {
        reserve_id(state, full_id);
        found_id = true;
        break;
      }
    }
    if (!found_id) {
      PI_LOG_ERROR("All the ids provided for object '%s' or already taken\n",
                   name);
      exit(1);
    }
  }
}

static int add_field_bitwidth(reader_state_t *state, char *fname, size_t bw) {
  field_bitwidth_t *f_bw;
  HASH_FIND_STR(state->fields_bitwidth, fname, f_bw);
  if (f_bw) return 0;
  f_bw = malloc(sizeof(*f_bw));
  f_bw->name = fname;
  f_bw->bitwidth = bw;
  HASH_ADD_KEYPTR(hh, state->fields_bitwidth, f_bw->name, strlen(f_bw->name),
                  f_bw);
  return 1;
}

static const size_t *get_field_bitwidth(reader_state_t *state,
                                        const char *fname) {
  field_bitwidth_t *f_bw;
  HASH_FIND_STR(state->fields_bitwidth, fname, f_bw);
  if (!f_bw) return NULL;
  return &f_bw->bitwidth;
}

// taken from https://en.wikipedia.org/wiki/Jenkins_hash_function
static uint32_t jenkins_one_at_a_time_hash(const uint8_t *key, size_t length) {
  size_t i = 0;
  uint32_t hash = 0;
  while (i != length) {
    hash += key[i++];
    hash += hash << 10;
    hash ^= hash >> 6;
  }
  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;
  return hash;
}

static uint32_t hash_to_id(uint32_t hash, pi_res_type_id_t type_id) {
  return (type_id << 24) | (hash & 0xffff);
}

static pi_p4_id_t generate_id_from_name(reader_state_t *state, cJSON *object,
                                        pi_res_type_id_t type_id) {
  const cJSON *item = cJSON_GetObjectItem(object, "name");
  const char *name = item->valuestring;
  pi_p4_id_t hash =
      jenkins_one_at_a_time_hash((const uint8_t *)name, strlen(name));
  while (is_id_reserved(state, hash_to_id(hash, type_id))) hash++;
  pi_p4_id_t id = hash_to_id(hash, type_id);
  reserve_id(state, id);
  allocate_id(state, id);
  return id;
}

static pi_p4_id_t request_id(reader_state_t *state, cJSON *object,
                             pi_res_type_id_t type_id) {
  pi_p4_id_t ids[MAX_IDS_IN_ANNOTATION];
  size_t num_ids = 0;
  find_annotation_id(object, ids, &num_ids);
  pi_p4_id_t id;
  if (num_ids != 0) {
    for (size_t i = 0; i < num_ids; i++) {
      id = (type_id << 24) | ids[i];
      assert(is_id_reserved(state, id));
      if (!is_id_allocated(state, id)) {
        allocate_id(state, id);
        return id;
      }
    }
  }
  return generate_id_from_name(state, object, type_id);
}

static void import_pragmas(cJSON *object, pi_p4info_t *p4info, pi_p4_id_t id) {
  cJSON *pragmas = cJSON_GetObjectItem(object, "pragmas");
  if (!pragmas) return;
  cJSON *pragma;
  cJSON_ArrayForEach(pragma, pragmas) {
    pi_p4info_add_annotation(p4info, id, pragma->valuestring);
  }
}

// a simple bubble sort to sort objects in a list based on alphabetical order of
// their name attribute
static void sort_json_array(cJSON *array) {
  assert(array->type == cJSON_Array);
  int size = cJSON_GetArraySize(array);
  const cJSON *item = NULL;
  for (int i = size - 1; i > 0; i--) {
    cJSON *object = array->child;
    cJSON *next_object = NULL;
    cJSON **prev_ptr = &(array->child);
    while (object->next) {
      next_object = object->next;
      item = cJSON_GetObjectItem(object, "name");
      const char *name = item->valuestring;
      item = cJSON_GetObjectItem(next_object, "name");
      const char *next_name = item->valuestring;

      if (strcmp(name, next_name) > 0) {  // do swap
        *prev_ptr = next_object;
        next_object->prev = *prev_ptr;
        object->prev = next_object;
        object->next = next_object->next;
        next_object->next = object;
      }
      prev_ptr = &(object->next);
      object = next_object;
    }
    array->child->prev = NULL;
  }
}

static pi_status_t read_actions(reader_state_t *state, cJSON *root,
                                pi_p4info_t *p4info) {
  assert(root);
  cJSON *actions = cJSON_GetObjectItem(root, "actions");
  if (!actions) return PI_STATUS_CONFIG_READER_ERROR;
  pre_reserve_ids(state, PI_ACTION_ID, actions);
  size_t num_actions = cJSON_GetArraySize(actions);
  pi_p4info_action_init(p4info, num_actions);

  cJSON *action;
  sort_json_array(actions);
  cJSON_ArrayForEach(action, actions) {
    const cJSON *item;
    item = cJSON_GetObjectItem(action, "name");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *name = item->valuestring;
    pi_p4_id_t pi_id = request_id(state, action, PI_ACTION_ID);

    cJSON *params = cJSON_GetObjectItem(action, "runtime_data");
    if (!params) return PI_STATUS_CONFIG_READER_ERROR;
    size_t num_params = cJSON_GetArraySize(params);

    PI_LOG_DEBUG("Adding action '%s'\n", name);
    pi_p4info_action_add(p4info, pi_id, name, num_params);

    int param_index = 1;
    cJSON *param;
    cJSON_ArrayForEach(param, params) {
      item = cJSON_GetObjectItem(param, "name");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      const char *param_name = item->valuestring;

      item = cJSON_GetObjectItem(param, "bitwidth");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      int param_bitwidth = item->valueint;

      pi_p4_id_t param_id = param_index++;
      pi_p4info_action_add_param(p4info, pi_id, param_id, param_name,
                                 param_bitwidth);
    }

    import_pragmas(action, p4info, pi_id);
  }

  return PI_STATUS_SUCCESS;
}

// rules to exclude fields
static bool exclude_field(const char *suffix) {
  // exclude "padding" fields, i.e. fields which start with "_padding"
  if (!strncmp(suffix, "_padding", sizeof "_padding" - 1)) return true;
  return false;
}

typedef struct {
  const char *header_name;
  cJSON *header_type;
  UT_hash_handle hh;
} header_type_hash_t;

// rules to exclude header instances
static bool exclude_header(cJSON *header) {
  (void)header;
  return false;
  // For some reason the new p4c compiler always sets pi_omit to true
  // Now that we do not have "fields" in p4info anymore, this check is probably
  // not even relevant anymore.
  /* const cJSON *item = cJSON_GetObjectItem(header, "pi_omit"); */
  /* if (!item) return false; */
  /* if (item->valueint) return true; */
  /* return false; */
}

static pi_status_t read_fields(reader_state_t *state, cJSON *root) {
  assert(root);
  cJSON *headers = cJSON_GetObjectItem(root, "headers");
  if (!headers) return PI_STATUS_CONFIG_READER_ERROR;

  cJSON *header_types = cJSON_GetObjectItem(root, "header_types");
  if (!header_types) return PI_STATUS_CONFIG_READER_ERROR;

  header_type_hash_t *header_type_map = NULL;

  cJSON *item;

  cJSON *header_type;
  cJSON_ArrayForEach(header_type, header_types) {
    item = cJSON_GetObjectItem(header_type, "name");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *name = item->valuestring;

    header_type_hash_t *header_type_hash;
    HASH_FIND_STR(header_type_map, name, header_type_hash);
    if (header_type_hash) return PI_STATUS_CONFIG_READER_ERROR;  // duplicate
    header_type_hash = malloc(sizeof(*header_type_hash));
    header_type_hash->header_name = name;
    header_type_hash->header_type = header_type;
    HASH_ADD_KEYPTR(hh, header_type_map, name, strlen(name), header_type_hash);
  }

  cJSON *header;
  cJSON_ArrayForEach(header, headers) {
    if (exclude_header(header)) continue;
    item = cJSON_GetObjectItem(header, "name");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *header_name = item->valuestring;
    item = cJSON_GetObjectItem(header, "header_type");
    const char *header_type_name = item->valuestring;
    header_type_hash_t *header_type_hash;
    HASH_FIND_STR(header_type_map, header_type_name, header_type_hash);
    if (!header_type_hash) return PI_STATUS_CONFIG_READER_ERROR;
    item = header_type_hash->header_type;
    item = cJSON_GetObjectItem(item, "fields");
    cJSON *field;
    cJSON_ArrayForEach(field, item) {
      const char *suffix = cJSON_GetArrayItem(field, 0)->valuestring;
      if (exclude_field(suffix)) continue;

      //  just a safeguard, given how we handle validity
      if (!strncmp("$valid$", suffix, sizeof "$valid$")) {
        PI_LOG_ERROR("Fields cannot have name '$valid$'");
        return PI_STATUS_CONFIG_READER_ERROR;
      }

      char fname[256];
      int n = snprintf(fname, sizeof(fname), "%s.%s", header_name, suffix);
      if (n <= 0 || (size_t)n >= sizeof(fname)) return PI_STATUS_BUFFER_ERROR;
      size_t bitwidth = (size_t)cJSON_GetArrayItem(field, 1)->valueint;

      if (!add_field_bitwidth(state, strdup(fname), bitwidth))
        return PI_STATUS_CONFIG_READER_ERROR;  // duplicate
    }
    // Adding a field to represent validity, don't know how temporary this is
    {
      char fname[256];
      int n = snprintf(fname, sizeof(fname), "%s.$valid$", header_name);
      if (n <= 0 || (size_t)n >= sizeof(fname)) return PI_STATUS_BUFFER_ERROR;

      // 1 bit field
      if (!add_field_bitwidth(state, strdup(fname), 1))
        return PI_STATUS_CONFIG_READER_ERROR;  // duplicate
    }
  }

  header_type_hash_t *header_type_hash, *tmp;
  // deletion-safe iteration
  HASH_ITER(hh, header_type_map, header_type_hash, tmp) {
    HASH_DEL(header_type_map, header_type_hash);
    free(header_type_hash);
  }

  return PI_STATUS_SUCCESS;
}

static pi_p4info_match_type_t match_type_from_str(const char *type) {
  if (!strncmp("valid", type, sizeof "valid"))
    return PI_P4INFO_MATCH_TYPE_VALID;
  if (!strncmp("exact", type, sizeof "exact"))
    return PI_P4INFO_MATCH_TYPE_EXACT;
  if (!strncmp("lpm", type, sizeof "lpm")) return PI_P4INFO_MATCH_TYPE_LPM;
  if (!strncmp("ternary", type, sizeof "ternary"))
    return PI_P4INFO_MATCH_TYPE_TERNARY;
  if (!strncmp("range", type, sizeof "range"))
    return PI_P4INFO_MATCH_TYPE_RANGE;
  assert(0 && "unsupported match type");
  return PI_P4INFO_MATCH_TYPE_END;
}

static int cmp_json_object_generic(const void *e1, const void *e2) {
  cJSON *object_1 = *(cJSON *const *)e1;
  cJSON *object_2 = *(cJSON *const *)e2;
  const cJSON *item_1, *item_2;
  item_1 = cJSON_GetObjectItem(object_1, "name");
  item_2 = cJSON_GetObjectItem(object_2, "name");
  return strcmp(item_1->valuestring, item_2->valuestring);
}

// common code for action profiles and tables, returns NULL in case of incorrect
// JSON input
static vector_t *extract_from_pipelines(reader_state_t *state, cJSON *root,
                                        const char *res_name,
                                        pi_res_type_id_t res_type) {
  cJSON *pipelines = cJSON_GetObjectItem(root, "pipelines");
  if (!pipelines) return NULL;

  // cannot use sort_json_array as we have to sort them across multiple
  // pipelines so instead we create a temporary vector which we sort with qsort
  const size_t init_capacity = 16;
  vector_t *res_vec = vector_create(sizeof(cJSON *), init_capacity);
  cJSON *entry;
  cJSON *pipe;
  cJSON_ArrayForEach(pipe, pipelines) {
    cJSON *entries = cJSON_GetObjectItem(pipe, res_name);
    if (!entries) return NULL;
    pre_reserve_ids(state, res_type, entries);
    cJSON_ArrayForEach(entry, entries) {
      vector_push_back(res_vec, (void *)&entry);
    }
  }
  qsort(vector_data(res_vec), vector_size(res_vec), sizeof(cJSON *),
        cmp_json_object_generic);
  return res_vec;
}

static pi_status_t read_act_profs(reader_state_t *state, cJSON *root,
                                  pi_p4info_t *p4info) {
  assert(root);
  vector_t *act_profs_vec =
      extract_from_pipelines(state, root, "action_profiles", PI_ACT_PROF_ID);
  if (!act_profs_vec) return PI_STATUS_CONFIG_READER_ERROR;
  size_t num_act_profs = vector_size(act_profs_vec);
  pi_p4info_act_prof_init(p4info, num_act_profs);

  for (size_t i = 0; i < num_act_profs; i++) {
    cJSON *act_prof = *(cJSON **)vector_at(act_profs_vec, i);
    const cJSON *item;
    item = cJSON_GetObjectItem(act_prof, "name");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *name = item->valuestring;
    pi_p4_id_t pi_id = request_id(state, act_prof, PI_ACT_PROF_ID);
    bool with_selector = cJSON_HasObjectItem(act_prof, "selector");
    item = cJSON_GetObjectItem(act_prof, "max_size");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    size_t max_size = item->valueint;
    PI_LOG_DEBUG("Adding action profile '%s'\n", name);
    pi_p4info_act_prof_add(p4info, pi_id, name, with_selector, max_size);
  }

  vector_destroy(act_profs_vec);

  return PI_STATUS_SUCCESS;
}

static pi_status_t read_tables(reader_state_t *state, cJSON *root,
                               pi_p4info_t *p4info) {
  assert(root);
  vector_t *tables_vec =
      extract_from_pipelines(state, root, "tables", PI_TABLE_ID);
  if (!tables_vec) return PI_STATUS_CONFIG_READER_ERROR;
  size_t num_tables = vector_size(tables_vec);
  pi_p4info_table_init(p4info, num_tables);

  for (size_t i = 0; i < num_tables; i++) {
    cJSON *table = *(cJSON **)vector_at(tables_vec, i);
    const cJSON *item;
    item = cJSON_GetObjectItem(table, "name");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *name = item->valuestring;
    pi_p4_id_t pi_id = request_id(state, table, PI_TABLE_ID);

    cJSON *json_match_key = cJSON_GetObjectItem(table, "key");
    if (!json_match_key) return PI_STATUS_CONFIG_READER_ERROR;
    size_t num_match_fields = cJSON_GetArraySize(json_match_key);

    cJSON *json_actions = cJSON_GetObjectItem(table, "actions");
    if (!json_actions) return PI_STATUS_CONFIG_READER_ERROR;
    size_t num_actions = cJSON_GetArraySize(json_actions);

    item = cJSON_GetObjectItem(table, "max_size");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    size_t max_size = item->valueint;

    cJSON *entries_array = cJSON_GetObjectItem(table, "entries");
    // true iff the table is immutable and entries cannot be added / modified at
    // runtime
    bool is_const = (entries_array && cJSON_GetArraySize(entries_array) > 0);

    item = cJSON_GetObjectItem(table, "support_timeout");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    if (item->type != cJSON_True && item->type != cJSON_False)
      return PI_STATUS_CONFIG_READER_ERROR;
    bool supports_idle_timeout = (item->type == cJSON_True);

    PI_LOG_DEBUG("Adding table '%s'\n", name);
    pi_p4info_table_add(p4info, pi_id, name, num_match_fields, num_actions,
                        max_size, is_const, supports_idle_timeout);

    import_pragmas(table, p4info, pi_id);

    cJSON *match_field;
    int match_field_index = 1;
    cJSON_ArrayForEach(match_field, json_match_key) {
      item = cJSON_GetObjectItem(match_field, "match_type");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      pi_p4info_match_type_t match_type =
          match_type_from_str(item->valuestring);

      cJSON *target = cJSON_GetObjectItem(match_field, "target");
      if (!target) return PI_STATUS_CONFIG_READER_ERROR;
      char fname[256];
      const char *header_name;
      const char *suffix;
      if (match_type == PI_P4INFO_MATCH_TYPE_VALID) {
        header_name = target->valuestring;
        suffix = "$valid$";
      } else {
        header_name = cJSON_GetArrayItem(target, 0)->valuestring;
        suffix = cJSON_GetArrayItem(target, 1)->valuestring;
      }
      int n = snprintf(fname, sizeof(fname), "%s.%s", header_name, suffix);
      if (n <= 0 || (size_t)n >= sizeof(fname)) return PI_STATUS_BUFFER_ERROR;
      pi_p4_id_t mf_id = match_field_index++;
      const size_t *bitwidth_ptr = get_field_bitwidth(state, fname);
      if (!bitwidth_ptr) return PI_STATUS_CONFIG_READER_ERROR;
      pi_p4info_table_add_match_field(p4info, pi_id, mf_id, fname, match_type,
                                      *bitwidth_ptr);
      // TODO(antonin): const default action
    }

    cJSON *action;
    cJSON_ArrayForEach(action, json_actions) {
      const char *aname = action->valuestring;
      pi_p4_id_t aid = pi_p4info_action_id_from_name(p4info, aname);
      pi_p4info_table_add_action(p4info, pi_id, aid,
                                 PI_P4INFO_ACTION_SCOPE_TABLE_AND_DEFAULT);
    }

    item = cJSON_GetObjectItem(table, "type");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *table_type = item->valuestring;
    const char *act_prof_name = NULL;
    // true for both 'indirect' and 'indirect_ws'
    if (!strncmp("indirect", table_type, sizeof "indirect" - 1)) {
      item = cJSON_GetObjectItem(table, "action_profile");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      act_prof_name = item->valuestring;
    }
    if (act_prof_name) {
      pi_p4_id_t pi_act_prof_id =
          pi_p4info_act_prof_id_from_name(p4info, act_prof_name);
      if (pi_act_prof_id == PI_INVALID_ID) return PI_STATUS_CONFIG_READER_ERROR;
      pi_p4info_act_prof_add_table(p4info, pi_act_prof_id, pi_id);
      pi_p4info_table_set_implementation(p4info, pi_id, pi_act_prof_id);
    }
  }

  vector_destroy(tables_vec);

  return PI_STATUS_SUCCESS;
}

static pi_status_t read_counters(reader_state_t *state, cJSON *root,
                                 pi_p4info_t *p4info) {
  assert(root);
  cJSON *counters = cJSON_GetObjectItem(root, "counter_arrays");
  if (!counters) return PI_STATUS_CONFIG_READER_ERROR;
  cJSON *counter;

  // first pass needed because PI treats indirect & direct counters differently:
  // we need to count and pre-reserve ids for counters of each type before we
  // actually add them to p4info.
  cJSON *counters_ = cJSON_CreateArray();
  cJSON *direct_counters_ = cJSON_CreateArray();
  size_t num_counters = 0, num_direct_counters = 0;
  cJSON_ArrayForEach(counter, counters) {
    const cJSON *item = cJSON_GetObjectItem(counter, "is_direct");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    bool is_direct = item->valueint;
    if (is_direct) {
      num_direct_counters++;
      cJSON_AddItemReferenceToArray(direct_counters_, counter);
    } else {
      num_counters++;
      cJSON_AddItemReferenceToArray(counters_, counter);
    }
  }
  pre_reserve_ids(state, PI_COUNTER_ID, counters_);
  cJSON_Delete(counters_);
  pi_p4info_counter_init(p4info, num_counters);
  pre_reserve_ids(state, PI_DIRECT_COUNTER_ID, direct_counters_);
  cJSON_Delete(direct_counters_);
  pi_p4info_direct_counter_init(p4info, num_direct_counters);

  sort_json_array(counters);
  cJSON_ArrayForEach(counter, counters) {
    const cJSON *item;
    item = cJSON_GetObjectItem(counter, "name");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *name = item->valuestring;

    item = cJSON_GetObjectItem(counter, "is_direct");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    bool is_direct = item->valueint;

    item = cJSON_GetObjectItem(counter, "size");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    size_t size = item->valueint;

    pi_p4_id_t pi_id;
    if (is_direct) {
      pi_id = request_id(state, counter, PI_DIRECT_COUNTER_ID);
      PI_LOG_DEBUG("Adding direct counter '%s'\n", name);
      item = cJSON_GetObjectItem(counter, "binding");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      const char *direct_tname = item->valuestring;
      pi_p4_id_t direct_tid =
          pi_p4info_table_id_from_name(p4info, direct_tname);
      if (direct_tid == PI_INVALID_ID) return PI_STATUS_CONFIG_READER_ERROR;
      pi_p4info_direct_counter_add(
          p4info, pi_id, name, PI_P4INFO_COUNTER_UNIT_BOTH, size, direct_tid);
      pi_p4info_table_add_direct_resource(p4info, direct_tid, pi_id);
    } else {
      pi_id = request_id(state, counter, PI_COUNTER_ID);
      PI_LOG_DEBUG("Adding counter '%s'\n", name);
      pi_p4info_counter_add(p4info, pi_id, name, PI_P4INFO_COUNTER_UNIT_BOTH,
                            size);
    }

    import_pragmas(counter, p4info, pi_id);
  }

  return PI_STATUS_SUCCESS;
}

static pi_p4info_meter_unit_t meter_unit_from_str(const char *unit) {
  if (!strncmp("packets", unit, sizeof "packets"))
    return PI_P4INFO_METER_UNIT_PACKETS;
  if (!strncmp("bytes", unit, sizeof "bytes"))
    return PI_P4INFO_METER_UNIT_BYTES;
  assert(0 && "unsupported meter unit type");
  return PI_P4INFO_METER_UNIT_PACKETS;
}

static pi_status_t read_meters(reader_state_t *state, cJSON *root,
                               pi_p4info_t *p4info) {
  assert(root);
  cJSON *meters = cJSON_GetObjectItem(root, "meter_arrays");
  if (!meters) return PI_STATUS_CONFIG_READER_ERROR;
  cJSON *meter;

  // first pass needed because PI treats indirect & direct meters differently:
  // we need to count and pre-reserve ids for meters of each type before we
  // actually add them to p4info.
  cJSON *meters_ = cJSON_CreateArray();
  cJSON *direct_meters_ = cJSON_CreateArray();
  size_t num_meters = 0, num_direct_meters = 0;
  cJSON_ArrayForEach(meter, meters) {
    const cJSON *item = cJSON_GetObjectItem(meter, "is_direct");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    bool is_direct = item->valueint;
    if (is_direct) {
      num_direct_meters++;
      cJSON_AddItemReferenceToArray(direct_meters_, meter);
    } else {
      num_meters++;
      cJSON_AddItemReferenceToArray(meters_, meter);
    }
  }
  pre_reserve_ids(state, PI_METER_ID, meters_);
  cJSON_Delete(meters_);
  pi_p4info_meter_init(p4info, num_meters);
  pre_reserve_ids(state, PI_DIRECT_METER_ID, direct_meters_);
  cJSON_Delete(direct_meters_);
  pi_p4info_direct_meter_init(p4info, num_direct_meters);

  sort_json_array(meters);
  cJSON_ArrayForEach(meter, meters) {
    const cJSON *item;
    item = cJSON_GetObjectItem(meter, "name");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *name = item->valuestring;

    item = cJSON_GetObjectItem(meter, "is_direct");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    bool is_direct = item->valueint;

    item = cJSON_GetObjectItem(meter, "size");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    size_t size = item->valueint;

    item = cJSON_GetObjectItem(meter, "type");
    if (!item) return PI_STATUS_CONFIG_READER_ERROR;
    const char *meter_unit_str = item->valuestring;
    pi_p4info_meter_unit_t meter_unit = meter_unit_from_str(meter_unit_str);

    pi_p4_id_t pi_id;
    if (is_direct) {
      pi_id = request_id(state, meter, PI_DIRECT_METER_ID);
      PI_LOG_DEBUG("Adding direct meter '%s'\n", name);
      item = cJSON_GetObjectItem(meter, "binding");
      if (!item) return PI_STATUS_CONFIG_READER_ERROR;
      const char *direct_tname = item->valuestring;
      pi_p4_id_t direct_tid =
          pi_p4info_table_id_from_name(p4info, direct_tname);
      if (direct_tid == PI_INVALID_ID) return PI_STATUS_CONFIG_READER_ERROR;
      // color unaware by default
      pi_p4info_direct_meter_add(p4info, pi_id, name, meter_unit,
                                 PI_P4INFO_METER_TYPE_COLOR_UNAWARE, size,
                                 direct_tid);
      pi_p4info_table_add_direct_resource(p4info, direct_tid, pi_id);
    } else {
      pi_id = request_id(state, meter, PI_METER_ID);
      PI_LOG_DEBUG("Adding meter '%s'\n", name);
      // color unaware by default
      pi_p4info_meter_add(p4info, pi_id, name, meter_unit,
                          PI_P4INFO_METER_TYPE_COLOR_UNAWARE, size);
    }

    import_pragmas(meter, p4info, pi_id);
  }

  return PI_STATUS_SUCCESS;
}

static pi_status_t read_digests(reader_state_t *state, cJSON *root,
                                pi_p4info_t *p4info) {
  (void)state;
  (void)root;
  assert(root);
  // TODO(antonin): skeleton so that unit tests pass, implement later if needed
  pi_p4info_digest_init(p4info, 0);
  return PI_STATUS_SUCCESS;
}

static bool check_json_version(cJSON *root) {
  cJSON *item;
  item = cJSON_GetObjectItem(root, "__meta__");
  if (!item) return false;
  item = cJSON_GetObjectItem(item, "version");
  if (!item) return false;
  const cJSON *major = cJSON_GetArrayItem(item, 0);
  const cJSON *minor = cJSON_GetArrayItem(item, 1);
  if (!major || !minor) return false;
  if (major->valueint != required_major_version) return false;
  if (minor->valueint < min_minor_version) return false;
  return true;
}

pi_status_t pi_bmv2_json_reader(const char *config, pi_p4info_t *p4info) {
  cJSON *root = cJSON_Parse(config);
  if (!root) return PI_STATUS_CONFIG_READER_ERROR;

  pi_status_t status;

  if (!check_json_version(root)) {
    PI_LOG_ERROR("Json version requirement not satisfied!\n");
    return PI_STATUS_CONFIG_READER_ERROR;
  }

  reader_state_t state;
  init_reader_state(&state);

  if ((status = read_actions(&state, root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  if ((status = read_fields(&state, root)) != PI_STATUS_SUCCESS) {
    return status;
  }

  if ((status = read_act_profs(&state, root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  if ((status = read_tables(&state, root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  if ((status = read_counters(&state, root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  if ((status = read_meters(&state, root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  if ((status = read_digests(&state, root, p4info)) != PI_STATUS_SUCCESS) {
    return status;
  }

  cJSON_Delete(root);

  destroy_reader_state(&state);

  return PI_STATUS_SUCCESS;
}
