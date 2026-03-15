/* Copyright 2018-present Barefoot Networks, Inc.
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

#include "PI/p4info/digests.h"
#include "PI/int/pi_int.h"
#include "digests_int.h"
#include "p4info/p4info_struct.h"

#include <cJSON/cJSON.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define INLINE_FIELDS 8

typedef struct {
  char *name;
  size_t bitwidth;
} _digest_field_data_t;

typedef struct _digest_data_s {
  p4info_common_t common;
  char *name;
  pi_p4_id_t digest_id;
  size_t num_fields;
  union {
    _digest_field_data_t direct[INLINE_FIELDS];
    _digest_field_data_t *indirect;
  } field_data;
  size_t digest_size;
  size_t fields_added;
} _digest_data_t;

static _digest_data_t *get_digest(const pi_p4info_t *p4info,
                                  pi_p4_id_t digest_id) {
  assert(PI_GET_TYPE_ID(digest_id) == PI_DIGEST_ID);
  return p4info_get_at(p4info, digest_id);
}

static _digest_field_data_t *get_field_data(_digest_data_t *digest) {
  return (digest->num_fields <= INLINE_FIELDS) ? digest->field_data.direct
                                               : digest->field_data.indirect;
}

static size_t num_digests(const pi_p4info_t *p4info) {
  return num_res(p4info, PI_DIGEST_ID);
}

static const char *retrieve_name(const void *data) {
  const _digest_data_t *digest = (const _digest_data_t *)data;
  return digest->name;
}

static void free_digest_data(void *data) {
  _digest_data_t *digest = (_digest_data_t *)data;
  if (!digest->name) return;
  free(digest->name);
  _digest_field_data_t *fields = get_field_data(digest);
  for (size_t j = 0; j < digest->num_fields; j++) {
    _digest_field_data_t *field = &fields[j];
    if (!field->name) continue;
    free(field->name);
  }
  if (digest->num_fields > INLINE_FIELDS) {
    assert(digest->field_data.indirect);
    free(digest->field_data.indirect);
  }
  p4info_common_destroy(&digest->common);
}

void pi_p4info_digest_serialize(cJSON *root, const pi_p4info_t *p4info) {
  cJSON *dArray = cJSON_CreateArray();
  const vector_t *digests = p4info->digests->vec;
  for (size_t i = 0; i < vector_size(digests); i++) {
    _digest_data_t *digest = vector_at(digests, i);
    cJSON *aObject = cJSON_CreateObject();

    cJSON_AddStringToObject(aObject, "name", digest->name);
    cJSON_AddNumberToObject(aObject, "id", digest->digest_id);

    cJSON *fArray = cJSON_CreateArray();
    _digest_field_data_t *field_data = get_field_data(digest);
    for (size_t j = 0; j < digest->num_fields; j++) {
      cJSON *f = cJSON_CreateObject();
      cJSON_AddStringToObject(f, "name", field_data[j].name);
      cJSON_AddNumberToObject(f, "bitwidth", field_data[j].bitwidth);
      cJSON_AddItemToArray(fArray, f);
    }
    cJSON_AddItemToObject(aObject, "fields", fArray);

    p4info_common_serialize(aObject, &digest->common);

    cJSON_AddItemToArray(dArray, aObject);
  }
  cJSON_AddItemToObject(root, "digests", dArray);
}

void pi_p4info_digest_init(pi_p4info_t *p4info, size_t num_digests) {
  p4info_init_res(p4info, PI_DIGEST_ID, num_digests, sizeof(_digest_data_t),
                  retrieve_name, free_digest_data, pi_p4info_digest_serialize);
}

void pi_p4info_digest_add(pi_p4info_t *p4info, pi_p4_id_t digest_id,
                          const char *name, size_t num_fields) {
  char *name_copy = strdup(name);
  _digest_data_t *digest = p4info_add_res(p4info, digest_id, name_copy);
  digest->name = name_copy;
  digest->digest_id = digest_id;
  digest->num_fields = num_fields;
  if (num_fields > INLINE_FIELDS) {
    digest->field_data.indirect =
        calloc(num_fields, sizeof(_digest_field_data_t));
  }
  digest->digest_size = 0;
  digest->fields_added = 0;
}

void pi_p4info_digest_add_field(pi_p4info_t *p4info, pi_p4_id_t digest_id,
                                const char *name, size_t bitwidth) {
  _digest_data_t *digest = get_digest(p4info, digest_id);
  assert(digest->fields_added < digest->num_fields);
  _digest_field_data_t *field_data =
      &get_field_data(digest)[digest->fields_added];
  field_data->name = strdup(name);
  field_data->bitwidth = bitwidth;

  digest->digest_size += (bitwidth + 7) / 8;

  digest->fields_added++;
}

size_t pi_p4info_digest_get_num(const pi_p4info_t *p4info) {
  return num_digests(p4info);
}

pi_p4_id_t pi_p4info_digest_id_from_name(const pi_p4info_t *p4info,
                                         const char *name) {
  return p4info_name_map_get(&p4info->digests->name_map, name);
}

const char *pi_p4info_digest_name_from_id(const pi_p4info_t *p4info,
                                          pi_p4_id_t digest_id) {
  _digest_data_t *digest = get_digest(p4info, digest_id);
  return digest->name;
}

size_t pi_p4info_digest_num_fields(const pi_p4info_t *p4info,
                                   pi_p4_id_t digest_id) {
  _digest_data_t *digest = get_digest(p4info, digest_id);
  if (digest == NULL)
    return (size_t)(-1);
  else
    return digest->num_fields;
}

const char *pi_p4info_digest_field_name(const pi_p4info_t *p4info,
                                        pi_p4_id_t digest_id, size_t idx) {
  _digest_data_t *digest = get_digest(p4info, digest_id);
  _digest_field_data_t *data = &get_field_data(digest)[idx];
  return data->name;
}

size_t pi_p4info_digest_field_bitwidth(const pi_p4info_t *p4info,
                                       pi_p4_id_t digest_id, size_t idx) {
  _digest_data_t *digest = get_digest(p4info, digest_id);
  _digest_field_data_t *data = &get_field_data(digest)[idx];
  return data->bitwidth;
}

size_t pi_p4info_digest_data_size(const pi_p4info_t *p4info,
                                  pi_p4_id_t digest_id) {
  _digest_data_t *digest = get_digest(p4info, digest_id);
  if (digest == NULL)
    return (size_t)(-1);
  else
    return digest->digest_size;
}

pi_p4_id_t pi_p4info_digest_begin(const pi_p4info_t *p4info) {
  return pi_p4info_any_begin(p4info, PI_DIGEST_ID);
}

pi_p4_id_t pi_p4info_digest_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  return pi_p4info_any_next(p4info, id);
}

pi_p4_id_t pi_p4info_digest_end(const pi_p4info_t *p4info) {
  return pi_p4info_any_end(p4info, PI_DIGEST_ID);
}
