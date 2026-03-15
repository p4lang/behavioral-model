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

#include <PI/frontends/proto/logging.h>

#include "logger.h"

namespace pi {

namespace fe {

namespace proto {

LoggerConfig::LoggerConfig() = default;

void
LoggerConfig::set_writer(std::shared_ptr<LogWriterIface> writer) {
  Logger::get()->set_writer(writer);
}

void
LoggerConfig::set_min_severity(Severity min_severity) {
  Logger::get()->set_min_severity(min_severity);
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
