/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2022 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
