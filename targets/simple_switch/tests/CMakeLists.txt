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
    Boost::system
    Boost::filesystem
    Boost::program_options
  )
  set_target_properties(ss_test_${TEST} PROPERTIES
    OUTPUT_NAME ${TEST}
  )
  add_test(NAME simple_switch/${TEST} COMMAND ${TEST})
endforeach()

# FIXME: should we have a test_all target?
