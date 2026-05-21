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

#ifndef _BMI_INTERFACE_
#define _BMI_INTERFACE_

typedef struct bmi_interface_s bmi_interface_t;

typedef enum
{
    bmi_input_dumper,
    bmi_output_dumper
}  bmi_dumper_kind_t;
    
int bmi_interface_create(bmi_interface_t **bmi, const char *device);

int bmi_interface_add_dumper(bmi_interface_t *bmi, const char *filename, bmi_dumper_kind_t dumper_kind);

int bmi_interface_destroy(bmi_interface_t *bmi);

int bmi_interface_send(bmi_interface_t *bmi, const char *data, int len);

int bmi_interface_recv(bmi_interface_t *bmi, const char **data);

int bmi_interface_recv_with_copy(bmi_interface_t *bmi, char *data, int max_len);

int bmi_interface_get_fd(bmi_interface_t *bmi);

#endif
