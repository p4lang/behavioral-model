// Copyright 2013 Google Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// adapted from
// https://github.com/google/lmctfy/blob/master/util/task/statusor.h

#ifndef SRC_STATUSOR_H_
#define SRC_STATUSOR_H_

#include <cassert>

#include "google/rpc/code.pb.h"
#include "google/rpc/status.pb.h"

namespace pi {

namespace fe {

namespace proto {

// A StatusOr holds a Status (in the case of an error), or a value T.
template <typename T>
class StatusOr {
 public:
  using Code = ::google::rpc::Code;
  using Status = ::google::rpc::Status;

  // Has status UNKNOWN.
  inline StatusOr();

  // Builds from a non-OK status. Crashes if an OK status is specified.
  inline StatusOr(const Status& status);  // NOLINT

  // Builds from the specified value.
  inline StatusOr(const T& value);  // NOLINT

  // Copy constructor.
  inline StatusOr(const StatusOr& other);

  // Conversion copy constructor, T must be copy constructible from U.
  template <typename U>
  inline StatusOr(const StatusOr<U>& other);

  // Assignment operator.
  inline const StatusOr& operator=(const StatusOr& other);

  // Conversion assignment operator, T must be assignable from U
  template<typename U>
  inline const StatusOr& operator=(const StatusOr<U>& other);

  // Accessors.
  inline const Status& status() const { return status_; }

  // Checks if status is ok.
  inline bool ok() const { return (status_.code() == Code::OK); }

  // Returns value or crashes if ok() is false.
  inline const T& ValueOrDie() const {
    assert(ok());
    return value_;
  }

  template<typename U> friend class StatusOr;

 private:
  Status status_;
  T value_;
};

// Implementation.

template <typename T>
inline StatusOr<T>::StatusOr() {
  status_.set_code(Code::UNKNOWN);
}

template <typename T>
inline StatusOr<T>::StatusOr(const Status& status)
    : status_(status) {
  assert(status.code() != Code::OK);
}

template <typename T>
inline StatusOr<T>::StatusOr(const T& value)
    : value_(value) {}

template <typename T>
inline StatusOr<T>::StatusOr(const StatusOr& other)
    : status_(other.status_), value_(other.value_) {
}

template <typename T>
template <typename U>
inline StatusOr<T>::StatusOr(const StatusOr<U>& other)
    : status_(other.status_), value_(other.value_) {
}

template <typename T>
inline const StatusOr<T>& StatusOr<T>::operator=(const StatusOr& other) {
  status_ = other.status_;
  if (ok()) {
    value_ = other.value_;
  }
  return *this;
}

template<typename T>
template<typename U>
inline const StatusOr<T>& StatusOr<T>::operator=(const StatusOr<U>& other) {
  status_ = other.status_;
  if (ok()) {
    value_ = other.value_;
  }
  return *this;
}

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_STATUSOR_H_
