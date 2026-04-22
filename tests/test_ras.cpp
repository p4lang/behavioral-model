// Copyright 2021 VMware, Inc.
// SPDX-FileCopyrightText: 2021 VMware, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas
 *
 */

#include <gtest/gtest.h>

#include <bm/bm_sim/ras.h>

#include <algorithm>
#include <vector>

using bm::RandAccessUIntSet;

class RandomAccessSetTest : public ::testing::Test { };

TEST_F(RandomAccessSetTest, LargeTestGetNth) {
  RandAccessUIntSet ras;
  std::vector<RandAccessUIntSet::mbr_t> mbrs;
  int size = 128;
  for (auto i = 0; i < size; i++) {
    auto mbr = static_cast<RandAccessUIntSet::mbr_t>(rand() % 65536);
    ras.add(mbr);
    mbrs.push_back(mbr);
  }
  std::sort(mbrs.begin(), mbrs.end());
  size_t nth = 0;
  for (auto i = 0; i < 10000; i++) {
    auto mbr = ras.get_nth(nth);
    ASSERT_EQ(mbrs[nth], mbr);
    nth = (nth + 10) % size;
  }
}
