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

#ifndef BM_PDFIXED_INT_PD_NOTIFICATIONS_H_
#define BM_PDFIXED_INT_PD_NOTIFICATIONS_H_

typedef void (*NotificationCb)(const char *hdr, const char *data);

int pd_notifications_add_device(int dev_id, const char *notifications_addr,
                                NotificationCb ageing_cb,
                                NotificationCb learning_cb);

int pd_notifications_remove_device(int dev_id);

#endif  // BM_PDFIXED_INT_PD_NOTIFICATIONS_H_
