# Include directories
include_directories(SYSTEM
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../third_party/gtest/include
)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/..
#  ${CMAKE_CURRENT_SOURCE_DIR}
#  ${CMAKE_SOURCE_DIR}/targets/test_utils
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
  test_basic
  test_grpc_dp
  test_packet_io
  test_counter
  test_meter
  test_ternary
  test_pre
  test_digest
  test_idle_timeout
  test_action_profile
  test_optional
  # test_gnmi
)

foreach(TEST ${TESTS})
  add_executable(ssg_test_${TEST}
    ${COMMON_SRCS}
    ${TEST}.cpp
  )
  target_include_directories(ssg_test_${TEST} PRIVATE
    ..
    ${CMAKE_BINARY_DIR}/services/cpp_out
    ${CMAKE_BINARY_DIR}/services/grpc_out
  )
  target_compile_options(ssg_test_${TEST} PRIVATE
    "-Wno-error=unused-result"
    "-Wno-error=deprecated-declarations"
  )
  target_link_libraries(ssg_test_${TEST}
    gtest
    simpleswitchgrpc
    simpleswitch
    piprotogrpc
    piprotobuf
    pifeproto
    pigrpcserver
    pi
    pip4info
    ${PROTOBUF_LIBRARIES}
    ${GRPCPP_LIBRARIES}
  )
  set_target_properties(ssg_test_${TEST} PROPERTIES
    OUTPUT_NAME ${TEST}
  )
  add_test(NAME simple_switch_grpc/${TEST} COMMAND ${TEST})
endforeach()

# FIXME: need to generate example.run from example.run.in
add_executable(example
  example.cpp
  utils.cpp
)
target_compile_options(example PRIVATE "-Wno-error=unused-result")
target_link_libraries(example
  piprotogrpc
  piprotobuf
  ${PROTOBUF_LIBRARIES}
  ${GRPCPP_LIBRARIES}
)

# FIXME: should we have a test_all target?

