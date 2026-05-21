// Copyright 2008 Google Inc.
// SPDX-FileCopyrightText: 2008 Google Inc.
//
// SPDX-License-Identifier: BSD-3-Clause

//
// Google C++ Mocking Framework (Google Mock)
//
// This file #includes all Google Mock implementation .cc files.  The
// purpose is to allow a user to build Google Mock by compiling this
// file alone.

// This line ensures that gmock.h can be compiled on its own, even
// when it's fused.
#include "gmock/gmock.h"

// The following lines pull in the real gmock *.cc files.
#include "src/gmock-cardinalities.cc"
#include "src/gmock-internal-utils.cc"
#include "src/gmock-matchers.cc"
#include "src/gmock-spec-builders.cc"
#include "src/gmock.cc"
