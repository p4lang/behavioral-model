// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <gtest/gtest.h>

#include <bm/bm_sim/queue.h>

#include <thread>
#include <random>
#include <tuple>

using std::unique_ptr;

using std::thread;

using bm::Queue;

using ::testing::TestWithParam;
using ::testing::Values;
using ::testing::Combine;

class QueueTest : public TestWithParam< std::tuple<size_t, int> > {
 protected:
  int iterations;
  size_t queue_size;

  unique_ptr<Queue<int> > queue;
  unique_ptr<int[]> values;

  virtual void SetUp() {
    queue_size = std::get<0>(GetParam());
    iterations = std::get<1>(GetParam());

    queue = unique_ptr<Queue<int> >(new Queue<int>(queue_size));
    values = unique_ptr<int[]>(new int[iterations]);

    std::mt19937 generator;
    std::uniform_int_distribution<int> distrib;
    for (int i = 0; i < iterations; i++) {
      values[i] = distrib(generator);
    }
  }

 public:
  void produce() {
    for (int i = 0; i < iterations; i++) {
      queue->push_front(values[i]);
    }
  }

  // virtual void TearDown() {}
};

static void producer(QueueTest *qt) {
  qt->produce();
}


TEST_P(QueueTest, ProducerConsumer) {
  thread producer_thread(producer, this);

  int value;
  for (int i = 0; i < iterations; i++) {
    queue->pop_back(&value);
    ASSERT_EQ(values[i], value);
  }

  producer_thread.join();
}


INSTANTIATE_TEST_SUITE_P(TestParameters,
                         QueueTest,
                         Combine(Values(16, 1024, 20000),
                                 Values(1000, 200000)));
