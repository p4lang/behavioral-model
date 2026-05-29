// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/phv_source.h>
#include <bm/bm_sim/phv.h>

#include <vector>
#include <mutex>
#include <iostream>

namespace bm {

class PHVSourceContextPools : public PHVSourceIface {
 public:
  explicit PHVSourceContextPools(size_t size)
      : phv_pools(size) { }

 private:
  class PHVPool {
   public:
    void set_phv_factory(const PHVFactory *factory) {
      std::unique_lock<std::mutex> lock(mutex);
      assert(count == 0);
      phv_factory = factory;
      phvs.clear();
    }

    std::unique_ptr<PHV> get() {
      std::unique_lock<std::mutex> lock(mutex);
      count++;
      if (phvs.size() == 0) {
        lock.unlock();
        return phv_factory->create();
      }
      std::unique_ptr<PHV> phv = std::move(phvs.back());
      phvs.pop_back();
      return phv;
    }

    void release(std::unique_ptr<PHV> phv) {
      std::unique_lock<std::mutex> lock(mutex);
      count--;
      phvs.push_back(std::move(phv));
    }

    size_t phvs_in_use() {
      std::unique_lock<std::mutex> lock(mutex);
      return count;
    }

   private:
    mutable std::mutex mutex{};
    std::vector<std::unique_ptr<PHV> > phvs{};
    const PHVFactory *phv_factory{nullptr};
    size_t count{0};
  };

  std::unique_ptr<PHV> get_(cxt_id_t cxt) override {
    return phv_pools.at(cxt).get();
  }

  void release_(cxt_id_t cxt, std::unique_ptr<PHV> phv) override {
    return phv_pools.at(cxt).release(std::move(phv));
  }

  void set_phv_factory_(cxt_id_t cxt, const PHVFactory *factory) override {
    phv_pools.at(cxt).set_phv_factory(factory);
  }

  size_t phvs_in_use_(cxt_id_t cxt) override {
    return phv_pools.at(cxt).phvs_in_use();
  }

  std::vector<PHVPool> phv_pools;
};

std::unique_ptr<PHV>
PHVSourceIface::get(cxt_id_t cxt) { return get_(cxt); }

void
PHVSourceIface::release(cxt_id_t cxt, std::unique_ptr<PHV> phv) {
  release_(cxt, std::move(phv));
}

void
PHVSourceIface::set_phv_factory(cxt_id_t cxt, const PHVFactory *factory) {
  set_phv_factory_(cxt, factory);
}

size_t
PHVSourceIface::phvs_in_use(cxt_id_t cxt) {
  return phvs_in_use_(cxt);
}

std::unique_ptr<PHVSourceIface>
PHVSourceIface::make_phv_source(size_t size) {
  return std::unique_ptr<PHVSourceContextPools>(
      new PHVSourceContextPools(size));
}

}  // namespace bm
