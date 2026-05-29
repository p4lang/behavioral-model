# SPDX-FileCopyrightText: 2025 Glen Gibb
#
# SPDX-License-Identifier: Apache-2.0

# Include directories
include_directories(SYSTEM
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../third_party/gtest/include
)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/..
#  ${CMAKE_CURRENT_SOURCE_DIR}
#  ${CMAKE_SOURCE_DIR}/targets/psa_test_utils
)

# Define test data directory
add_definitions(-DTESTDATADIR="${CMAKE_CURRENT_SOURCE_DIR}/testdata")

set(COMMON_SRCS
  main.cpp
  base_test.cpp
  utils.cpp
)

# Create test executables
set(TESTS
  psa_test_basic
  psa_test_grpc_dp
  psa_test_packet_io
  psa_test_counter
  psa_test_meter
  psa_test_ternary
  psa_test_pre
  psa_test_digest
  psa_test_idle_timeout
  psa_test_action_profile
  psa_test_optional
  # psa_test_gnmi
)

foreach(TEST ${TESTS})
  add_executable(ssg_psa_test_${TEST}
    ${COMMON_SRCS}
    ${TEST}.cpp
  )
  target_include_directories(ssg_psa_test_${TEST} PRIVATE
    ..
    ${CMAKE_BINARY_DIR}/services/cpp_out
    ${CMAKE_BINARY_DIR}/services/grpc_out
  )
  target_compile_options(ssg_psa_test_${TEST} PRIVATE
    "-Wno-error=unused-result"
    "-Wno-error=deprecated-declarations"
  )
  target_link_libraries(ssg_psa_test_${TEST}
    gtest
    psaswitchgrpc
    psaswitch
    piprotogrpc
    piprotobuf
    pifeproto
    pigrpcserver
    pi
    pip4info
    ${PROTOBUF_LIBRARIES}
    ${GRPCPP_LIBRARIES}
  )
  set_target_properties(ssg_psa_test_${TEST} PROPERTIES
    OUTPUT_NAME ${TEST}
  )
  # These tests don't play well when run in parallel; add them to a group call run_solo
  add_test(NAME psa_switch_grpc/${TEST} COMMAND ${TEST}
    CONFIGURATIONS run_solo
  )
endforeach()

# FIXME: need to generate example.run from example.run.in
add_executable(psa_example
  example.cpp
  utils.cpp
)
target_compile_options(psa_example PRIVATE "-Wno-error=unused-result")
target_link_libraries(psa_example
  piprotogrpc
  piprotobuf
  ${PROTOBUF_LIBRARIES}
  ${GRPCPP_LIBRARIES}
  Threads::Threads
)

# FIXME: should we have a psa_test_all target?

