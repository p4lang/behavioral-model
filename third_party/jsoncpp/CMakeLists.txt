# SPDX-FileCopyrightText: 2025 Glen Gibb
#
# SPDX-License-Identifier: Apache-2.0

# Create jsoncpp library
add_library(jsoncpp STATIC
  src/jsoncpp.cpp
)

# Set include directories
target_include_directories(jsoncpp PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
