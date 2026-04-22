# SPDX-FileCopyrightText: 2025 Glen Gibb
#
# SPDX-License-Identifier: Apache-2.0

# Should only be built if compiling with nanomsg

add_executable(test_packet_pipe
  test_packet_pipe.cpp
)

target_link_libraries(test_packet_pipe
  bmapps
)
