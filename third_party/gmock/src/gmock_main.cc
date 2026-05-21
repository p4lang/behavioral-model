// Copyright 2008 Google Inc.
// SPDX-FileCopyrightText: 2008 Google Inc.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <iostream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#if defined(GTEST_OS_ESP8266) || defined(GTEST_OS_ESP32) || \
    (defined(GTEST_OS_NRF52) && defined(ARDUINO))
#ifdef GTEST_OS_ESP8266
extern "C" {
#endif
void setup() {
  // Since Google Mock depends on Google Test, InitGoogleMock() is
  // also responsible for initializing Google Test.  Therefore there's
  // no need for calling testing::InitGoogleTest() separately.
  testing::InitGoogleMock();
}
void loop() { RUN_ALL_TESTS(); }
#ifdef GTEST_OS_ESP8266
}
#endif

#else

// MS C++ compiler/linker has a bug on Windows (not on Windows CE), which
// causes a link error when _tmain is defined in a static library and UNICODE
// is enabled. For this reason instead of _tmain, main function is used on
// Windows. See the following link to track the current status of this bug:
// https://web.archive.org/web/20170912203238/connect.microsoft.com/VisualStudio/feedback/details/394464/wmain-link-error-in-the-static-library
// // NOLINT
#ifdef GTEST_OS_WINDOWS_MOBILE
#include <tchar.h>  // NOLINT

GTEST_API_ int _tmain(int argc, TCHAR** argv) {
#else
GTEST_API_ int main(int argc, char** argv) {
#endif  // GTEST_OS_WINDOWS_MOBILE
  std::cout << "Running main() from gmock_main.cc\n";
  // Since Google Mock depends on Google Test, InitGoogleMock() is
  // also responsible for initializing Google Test.  Therefore there's
  // no need for calling testing::InitGoogleTest() separately.
  testing::InitGoogleMock(&argc, argv);
  return RUN_ALL_TESTS();
}
#endif
