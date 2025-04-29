# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/bm_sim
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/BMI
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../third_party/gtest/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../third_party/jsoncpp/include
)

# Define test data directory
add_definitions(-DTESTDATADIR="${CMAKE_CURRENT_SOURCE_DIR}/testdata")

# Create test executables
add_executable(test_packet_redirect test_packet_redirect.cpp)
target_link_libraries(test_packet_redirect
  gtest
  bmsim
  ${THRIFT_LIBRARIES}
  Boost::system
  Boost::filesystem
  Boost::program_options
)
add_test(NAME test_packet_redirect COMMAND test_packet_redirect)
