#!/bin/sh

# SPDX-FileCopyrightText: 2015 Anirudh Sivaraman
#
# SPDX-License-Identifier: Apache-2.0

# generates config.h.in
autoheader

autoreconf -fi
