# SPDX-FileCopyrightText: 2025 Glen Gibb
#
# SPDX-License-Identifier: Apache-2.0

# Include directories
include_directories(SYSTEM
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../third_party/gtest/include
)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/targets/test_utils
)

# Define test data directory
add_definitions(-DTESTDATADIR="${CMAKE_CURRENT_SOURCE_DIR}/testdata")

# Create test executables
set(TESTS
  test_packet_redirect
  test_truncate
  test_swap
  test_queueing
  test_recirc
  test_parser_error
)

foreach(TEST ${TESTS})
  add_executable(ss_test_${TEST} main.cpp ${TEST}.cpp)
  target_link_libraries(ss_test_${TEST}
    gtest
    bmapps
    bmsim
    simpleswitch
    test_utils
    ${THRIFT_LIBRARIES}
    Boost::program_options
  )
  set_target_properties(ss_test_${TEST} PROPERTIES
    OUTPUT_NAME ${TEST}
  )
  add_test(NAME simple_switch/${TEST} COMMAND ss_test_${TEST})
endforeach()

# Golden tests for the structured packet tracer. The runner sends each
# pipeline's scenario packets through an in-process simple_switch and prints
# the resulting packet traces; run_packet_trace_test.sh diffs that output
# against the checked-in testdata/<pipeline>.trace files.
if(ENABLE_PACKET_TRACE)
  add_executable(ss_test_packet_trace test_packet_trace.cpp)
  target_link_libraries(ss_test_packet_trace
    bmsim
    simpleswitch
    bm_packet_trace_proto
    ${THRIFT_LIBRARIES}
    Boost::program_options
  )
  set_target_properties(ss_test_packet_trace PROPERTIES
    OUTPUT_NAME test_packet_trace
  )

  set(PACKET_TRACE_PIPELINES
    packet_redirect
    parser_error
    queueing
    recirc
    truncate
  )

  foreach(PIPELINE ${PACKET_TRACE_PIPELINES})
    add_test(NAME simple_switch/packet_trace_${PIPELINE}
      COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run_packet_trace_test.sh
        $<TARGET_FILE:ss_test_packet_trace>
        ${CMAKE_CURRENT_SOURCE_DIR}/testdata
        ${PIPELINE}
    )
  endforeach()
endif()

# FIXME: should we have a test_all target?
