// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gtest/gtest.h>

bool WITH_VALGRIND = false;

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "--valgrind") == 0) {
      WITH_VALGRIND = true;
    }
  }
  return RUN_ALL_TESTS();
}

