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

#include "PI/pi_base.h"
#include "config_readers/readers.h"
#include "p4info_struct.h"
#include "read_file.h"
#include "tables_int.h"

#include <cJSON/cJSON.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

pi_status_t pi_empty_config(pi_p4info_t **p4info) {
  pi_p4info_t *p4info_ = malloc(sizeof(pi_p4info_t));
  memset(p4info_, 0, sizeof(*p4info_));

  // for convenience
  p4info_->actions = &p4info_->resources[PI_ACTION_ID];
  p4info_->tables = &p4info_->resources[PI_TABLE_ID];
  p4info_->act_profs = &p4info_->resources[PI_ACT_PROF_ID];
  p4info_->counters = &p4info_->resources[PI_COUNTER_ID];
  p4info_->direct_counters = &p4info_->resources[PI_DIRECT_COUNTER_ID];
  p4info_->meters = &p4info_->resources[PI_METER_ID];
  p4info_->direct_meters = &p4info_->resources[PI_DIRECT_METER_ID];
  p4info_->digests = &p4info_->resources[PI_DIGEST_ID];

  *p4info = p4info_;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_add_config(const char *config, pi_config_type_t config_type,
                          pi_p4info_t **p4info) {
  pi_status_t status = pi_empty_config(p4info);
  pi_p4info_t *p4info_ = *p4info;

  switch (config_type) {
    case PI_CONFIG_TYPE_NONE:
      status = PI_STATUS_SUCCESS;
      break;
    case PI_CONFIG_TYPE_BMV2_JSON:
      status = pi_bmv2_json_reader(config, p4info_);
      break;
    case PI_CONFIG_TYPE_NATIVE_JSON:
      status = pi_native_json_reader(config, p4info_);
      break;
    default:
      status = PI_STATUS_INVALID_CONFIG_TYPE;
      break;
  }
  if (status != PI_STATUS_SUCCESS) {
    free(p4info_);
    return status;
  }
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_add_config_from_file(const char *config_path,
                                    pi_config_type_t config_type,
                                    pi_p4info_t **p4info) {
  char *config_tmp = read_file(config_path);
  pi_status_t rc = pi_add_config(config_tmp, config_type, p4info);
  free(config_tmp);
  return rc;
}

pi_status_t pi_destroy_config(pi_p4info_t *p4info) {
  p4info_struct_destroy(p4info);
  free(p4info);
  return PI_STATUS_SUCCESS;
}

char *pi_serialize_config(const pi_p4info_t *p4info, int fmt) {
  cJSON *root = cJSON_CreateObject();

  for (size_t i = 0;
       i < sizeof(p4info->resources) / sizeof(p4info->resources[0]); i++) {
    const pi_p4info_res_t *res = &p4info->resources[i];
    if (!res->is_init) continue;
    assert(res->serialize_fn);
    res->serialize_fn(root, p4info);
  }

  // TODO(antonin): use cJSON_PrintBuffered for better performance if needed
  char *str = (fmt) ? cJSON_Print(root) : cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  return str;
}

void pi_free_serialized_config(char *config) { cJSON_Delete_char(config); }

int pi_serialize_config_to_fd(const pi_p4info_t *p4info, int fd, int fmt) {
  char *config = pi_serialize_config(p4info, fmt);
  if (!config) return -1;
  int bytes = dprintf(fd, "%s", config);
  pi_free_serialized_config(config);
  return bytes;
}

int pi_serialize_config_to_file(const pi_p4info_t *p4info, const char *path,
                                int fmt) {
  char *config = pi_serialize_config(p4info, fmt);
  FILE *f = fopen(path, "w");
  if (!f) return -1;
  int bytes = fprintf(f, "%s", config);
  pi_free_serialized_config(config);
  fclose(f);
  return bytes;
}
