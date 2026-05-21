// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
// Copyright 2013-present Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/logger.h>

#include <bm/spdlog/sinks/null_sink.h>

#include <iosfwd>
#include <memory>
#include <string>

namespace bm {

spdlog::logger *Logger::logger = nullptr;

void
Logger::set_logger_console() {
  unset_logger();
  auto logger_ = spdlog::stdout_logger_mt("bmv2");
  logger = logger_.get();
  set_pattern();
  logger_->set_level(to_spd_level(LogLevel::DEBUG));
}

void
Logger::set_logger_file(const std::string &filename, bool force_flush,
                         size_t max_size, size_t max_files) {
  unset_logger();
  auto logger_ = spdlog::rotating_logger_mt("bmv2", filename,
                                            max_size, max_files, force_flush);
  logger = logger_.get();
  set_pattern();
  logger_->set_level(to_spd_level(LogLevel::DEBUG));
}

void
Logger::set_logger_ostream(std::ostream &os) {
  unset_logger();
  auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(os);
  auto logger_ = std::make_shared<spdlog::logger>("bmv2", sink);
  spdlog::register_logger(logger_);
  logger = logger_.get();
  set_pattern();
  logger_->set_level(to_spd_level(LogLevel::DEBUG));
}

void
Logger::set_pattern() {
  logger->set_pattern("[%H:%M:%S.%e] [%n] [%L] [thread %t] %v");
}

void
Logger::unset_logger() {
  spdlog::drop("bmv2");
}

spdlog::logger *
Logger::init_logger() {
  if (logger != nullptr) return logger;
  auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
  auto null_logger = std::make_shared<spdlog::logger>("bmv2", null_sink);
  spdlog::register_logger(null_logger);
  logger = null_logger.get();
  return logger;
}

void
Logger::set_log_level(LogLevel level) {
  spdlog::logger *logger = get();
  logger->set_level(to_spd_level(level));
}

spdlog::level::level_enum
Logger::to_spd_level(LogLevel level) {
  namespace spdL = spdlog::level;
  switch (level) {
    case LogLevel::TRACE: return spdL::trace;
    case LogLevel::DEBUG: return spdL::debug;
    case LogLevel::INFO: return spdL::info;
    case LogLevel::NOTICE: return spdL::notice;
    case LogLevel::WARN: return spdL::warn;
    case LogLevel::ERROR: return spdL::err;
    case LogLevel::CRITICAL: return spdL::critical;
    case LogLevel::ALERT: return spdL::alert;
    case LogLevel::EMERG: return spdL::emerg;
    case LogLevel::OFF: return spdL::off;
    default: return spdL::off;
  }
}

}  // namespace bm
