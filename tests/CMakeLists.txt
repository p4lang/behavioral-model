# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/bm_sim
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/BMI
  ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/gtest/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/jsoncpp/include
)

# Define test data directory
add_definitions(-DTESTDATADIR="${CMAKE_CURRENT_SOURCE_DIR}/testdata")

# Skip undeterministic tests if requested
if(NOT ENABLE_UNDETERMINISTIC_TESTS)
  add_definitions(-DSKIP_UNDETERMINISTIC_TESTS)
endif()

# Configure utils.cpp
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/utils.cpp.in
  ${CMAKE_CURRENT_BINARY_DIR}/utils.cpp
  @ONLY
)

# Create test utilities library
add_library(testutils STATIC
  #utils.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/utils.cpp
)

target_link_libraries(testutils
  bmsim
)

# Common test sources
set(COMMON_SOURCES
  main.cpp
  bmi_stubs.c
  primitives.cpp
)

# Define test executables
set(TESTS
  test_actions
  test_checksums
  test_expressions
  test_conditionals
  test_data
  test_handle_mgr
  test_p4objects
  test_parser
  test_phv
  test_queue
  test_queueing
  test_tables
  test_learning
  test_pre
  test_calculations
  test_headers
  test_header_stacks
  test_header_unions
  test_meters
  test_ageing
  test_counters
  test_pcap
  test_fields
  test_devmgr
  test_packet
  test_extern
  test_periodic_tasks
  test_switch
  test_target_parser
  test_runtime_iface
  test_bm_apps
  test_stateful
  test_enums
  test_core_primitives
  test_control_flow
  test_assert_assume
  test_log_msg
  test_ras
)

# Create test executables
foreach(TEST_NAME ${TESTS})
  add_executable(${TEST_NAME} ${COMMON_SOURCES} ${TEST_NAME}.cpp)
  target_link_libraries(${TEST_NAME}
    gtest
    bmruntime
    bmapps
    bmsim
    bflpmtrie
    runtimestubs
    jsoncpp
    testutils
    ${THRIFT_LIBRARIES}
    Boost::system
    Boost::filesystem
    Boost::program_options
  )
  add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endforeach()

# Create test_all executable
add_executable(test_all 
  ${COMMON_SOURCES}
  test_actions.cpp
  test_checksums.cpp
  test_expressions.cpp
  test_conditionals.cpp
  test_data.cpp
  test_handle_mgr.cpp
  test_p4objects.cpp
  test_parser.cpp
  test_phv.cpp
  test_queue.cpp
  test_queueing.cpp
  test_tables.cpp
  test_learning.cpp
  test_pre.cpp
  test_calculations.cpp
  test_headers.cpp
  test_header_stacks.cpp
  test_header_unions.cpp
  test_meters.cpp
  test_ageing.cpp
  test_counters.cpp
  test_pcap.cpp
  test_fields.cpp
  test_devmgr.cpp
  test_packet.cpp
  test_extern.cpp
  test_periodic_tasks.cpp
  test_switch.cpp
  test_target_parser.cpp
  test_runtime_iface.cpp
  test_bm_apps.cpp
  test_stateful.cpp
  test_enums.cpp
  test_core_primitives.cpp
  test_control_flow.cpp
  test_assert_assume.cpp
  test_log_msg.cpp
  test_ras.cpp
)

target_link_libraries(test_all
  gtest
  bmruntime
  bmapps
  bmsim
  bflpmtrie
  runtimestubs
  jsoncpp
  testutils
  ${THRIFT_LIBRARIES}
  Boost::system
  Boost::filesystem
  Boost::program_options
)

# Add stress tests if enabled
if(WITH_STRESS_TESTS)
  add_subdirectory(stress_tests)
endif()

# Install test data
install(DIRECTORY testdata
  DESTINATION ${CMAKE_INSTALL_PREFIX}/share/behavioral-model/tests
)
