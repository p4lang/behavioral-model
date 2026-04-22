#!/bin/bash

# SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
# Copyright 2013-present Barefoot Networks, Inc.
#
# SPDX-License-Identifier: Apache-2.0

#
# Antonin Bas (antonin@barefootnetworks.com)
#
#

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

version_str="$(cat $THIS_DIR/../VERSION | tr -d '\n')"

bf_path="$THIS_DIR/../VERSION-build"
bversion_str=""
if [ -f $bf_path ]; then
    bversion_str="$(cat $bf_path | tr -d '\n')"
else
    if [ ! -d "$THIS_DIR/../.git" ]; then
        bversion_str="unknown"
    else
        git_sha_str="$(git rev-parse @)"
        if [ $? -ne 0 ]; then
            bversion_str="unknown"
        else
            bversion_str=${git_sha_str:0:8}
        fi
    fi
fi

version_str="$version_str-$bversion_str"

# Omit the trailing newline, so that m4_esyscmd can use the result directly.
printf %s "$version_str"
