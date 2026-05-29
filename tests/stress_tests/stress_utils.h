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

#ifndef TESTS_STRESS_TESTS_STRESS_UTILS_H_
#define TESTS_STRESS_TESTS_STRESS_UTILS_H_

#include <bm/bm_sim/_assert.h>
#include <bm/bm_sim/switch.h>

#include <chrono>
#include <vector>
#include <memory>
#include <string>

using std::chrono::milliseconds;
using std::chrono::duration_cast;

namespace stress_tests_utils {

class RandomGenImp;

class RandomGen {
 public:
  RandomGen();
  ~RandomGen();

  bool get_bool(double p_true);
  int get_int(int a, int b);

 private:
  std::unique_ptr<RandomGenImp> imp;
};

class SwitchTest : public bm::Switch {
 public:
  int receive_(port_t port_num, const char *buffer, int len) override {
    (void) port_num; (void) buffer; (void) len;
    return 0;
  }

  void start_and_return_() override {
  }

  // using pointers as most targets are expected to do that
  std::vector<std::unique_ptr<bm::Packet> > read_traffic(
      const std::string &path);
};

class TestChrono {
 public:
  using clock = std::chrono::high_resolution_clock;

  TestChrono(size_t packet_cnt);

  void start();
  void end();

  void print_summary();

 private:
  size_t packet_cnt;
  clock::time_point start_tp{};
  clock::time_point end_tp{};
};

}  // namespace stress_tests_utils

#endif  // TESTS_STRESS_TESTS_STRESS_UTILS_H_
