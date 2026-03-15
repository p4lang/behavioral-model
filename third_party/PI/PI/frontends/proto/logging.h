/* Copyright 2013-present Barefoot Networks, Inc.
 * SPDX-License-Identifier: Apache-2.0
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

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef PI_FRONTENDS_PROTO_LOGGING_H_
#define PI_FRONTENDS_PROTO_LOGGING_H_

#include <memory>

namespace pi {

namespace fe {

namespace proto {

class LogWriterIface {
 public:
  enum class Severity {
    TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL
  };

  virtual ~LogWriterIface() { }

  virtual void write(Severity severity, const char *msg) {
    (void) severity;
    (void) msg;
  }
};

class LoggerConfig {
 public:
  using Severity = LogWriterIface::Severity;

  // configuration methods are not thread-safe
  static void set_writer(std::shared_ptr<LogWriterIface> writer);
  static void set_min_severity(Severity min_severity);

 private:
  LoggerConfig();
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // PI_FRONTENDS_PROTO_LOGGING_H_
