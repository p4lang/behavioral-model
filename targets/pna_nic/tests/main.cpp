// Copyright 2024 Marvell Technology, Inc.
// SPDX-FileCopyrightText: 2024 Marvell Technology, Inc.
//
// SPDX-License-Identifier: Apache-2.0
 
/*
 * Rupesh Chiluka (rchiluka@marvell.com)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gtest/gtest.h>

bool WITH_VALGRIND = false;

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
