/* Copyright 2013-present Barefoot Networks, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SRC_REPORT_ERROR_H_
#define SRC_REPORT_ERROR_H_
#include "fmt/format.h"
#include "google/rpc/code.pb.h"
#include "logger.h"
namespace pi {
namespace fe {
namespace proto {
template <typename Arg1, typename... Args>
static inline ::google::rpc::Status ERROR_STATUS(::google::rpc::Code code,
                                                 const char *format_str,
                                                 const Arg1 &arg1,
                                                 const Args &... args) {
  ::google::rpc::Status status;
  status.set_code(code);
  auto msg = fmt::format(format_str, arg1, args...);
  status.set_message(msg);
  Logger::get()->error(msg);
  return status;
}
template <typename Arg>
static inline ::google::rpc::Status ERROR_STATUS(::google::rpc::Code code,
                                                 const Arg &msg) {
  ::google::rpc::Status status;
  status.set_code(code);
  status.set_message(msg);
  Logger::get()->error(msg);
  return status;
}
static inline ::google::rpc::Status ERROR_STATUS(::google::rpc::Code code) {
  ::google::rpc::Status status;
  status.set_code(code);
  return status;
}
static inline ::google::rpc::Status OK_STATUS() {
  ::google::rpc::Status status;
  status.set_code(::google::rpc::Code::OK);
  return status;
}
static inline ::google::rpc::Status GENERIC_STATUS(::google::rpc::Code code) {
  ::google::rpc::Status status;
  status.set_code(code);
  return status;
}
}  // namespace proto
}  // namespace fe
}  // namespace pi
#define RETURN_OK_STATUS() return ::pi::fe::proto::OK_STATUS();
#define RETURN_ERROR_STATUS(...) \
  return ::pi::fe::proto::ERROR_STATUS(__VA_ARGS__);
#define RETURN_STATUS(code) return ::pi::fe::proto::GENERIC_STATUS(code);
#define IS_OK(status) (status.code() == ::google::rpc::Code::OK)
#define IS_ERROR(status) (status.code() != ::google::rpc::Code::OK)
#define RETURN_IF_ERROR(status)                 \
  do {                                          \
    auto status_ = status;                      \
    if (IS_ERROR(status_)) return status_;      \
  }                                             \
  while (false)
#endif  // SRC_REPORT_ERROR_H_
