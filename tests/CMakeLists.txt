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
set(top_srcdir ${CMAKE_SOURCE_DIR})
set(top_builddir ${CMAKE_BINARY_DIR})
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
  test_ageing
  test_assert_assume
  test_bm_apps
  test_calculations
  test_checksums
  test_conditionals
  test_control_flow
  test_core_primitives
  test_counters
  test_data
  test_devmgr
  test_enums
  test_expressions
  test_extern
  test_fields
  test_handle_mgr
  test_header_stacks
  test_header_unions
  test_headers
  test_learning
  test_log_msg
  test_meters
  test_p4objects
  test_packet
  test_parser
  test_pcap
  test_periodic_tasks
  test_phv
  test_pre
  test_queue
  test_queueing
  test_ras
  test_runtime_iface
  test_stateful
  test_switch
  test_tables
  test_target_parser
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
  target_compile_options(${TEST_NAME} PRIVATE "-Wno-error")
  add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endforeach()

# Create test_all executable
add_executable(test_all 
  ${COMMON_SOURCES}
  test_actions.cpp
  test_ageing.cpp
  test_assert_assume.cpp
  test_bm_apps.cpp
  test_calculations.cpp
  test_checksums.cpp
  test_conditionals.cpp
  test_control_flow.cpp
  test_core_primitives.cpp
  test_counters.cpp
  test_data.cpp
  test_devmgr.cpp
  test_enums.cpp
  test_expressions.cpp
  test_extern.cpp
  test_fields.cpp
  test_handle_mgr.cpp
  test_header_stacks.cpp
  test_header_unions.cpp
  test_headers.cpp
  test_learning.cpp
  test_log_msg.cpp
  test_meters.cpp
  test_p4objects.cpp
  test_packet.cpp
  test_parser.cpp
  test_pcap.cpp
  test_periodic_tasks.cpp
  test_phv.cpp
  test_pre.cpp
  test_queue.cpp
  test_queueing.cpp
  test_ras.cpp
  test_runtime_iface.cpp
  test_stateful.cpp
  test_switch.cpp
  test_tables.cpp
  test_target_parser.cpp
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

target_compile_options(test_all PRIVATE "-Wno-error")

# Add stress tests if enabled
if(WITH_STRESS_TESTS)
  add_subdirectory(stress_tests)
endif()

# Install test data
install(DIRECTORY testdata
  DESTINATION ${CMAKE_INSTALL_PREFIX}/share/behavioral-model/tests
)
