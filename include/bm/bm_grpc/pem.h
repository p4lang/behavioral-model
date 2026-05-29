/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 * Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2022 VMware, Inc.
 * SPDX-FileCopyrightText: 2022 VMware, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BM_BM_GRPC_PEM_H_
#define BM_BM_GRPC_PEM_H_

#include <exception>
#include <fstream>
#include <sstream>
#include <streambuf>
#include <string>

namespace bm {

class read_pem_exception : public std::exception {
 public:
  read_pem_exception(const std::string &filename, const std::string &error)
      : filename(filename), error(error) { }

  std::string msg() const {
    std::stringstream ss;
    ss << "Error when reading pem file '" << filename << "': " << error << "\n";
    return ss.str();
  }

  const char *what() const noexcept override {
    return error.c_str();
  }

 private:
  std::string filename;
  std::string error;
};

std::string read_pem_file(const std::string &filename) {
  std::ifstream fs(filename, std::ios::in);
  if (!fs) {
    throw read_pem_exception(filename, "file cannot be opened");
  }
  return std::string((std::istreambuf_iterator<char>(fs)),
                     std::istreambuf_iterator<char>());
}

}  // namespace bm

#endif  // BM_BM_GRPC_PEM_H_
