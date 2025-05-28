# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../BMI
  ${CMAKE_CURRENT_SOURCE_DIR}/../bf_lpm_trie
)

# Configure version.cpp
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/version.cpp.in
  ${CMAKE_CURRENT_BINARY_DIR}/version.cpp
  @ONLY
)

# Create bmsim library
add_library(bmsim OBJECT
  _assert.cpp
  action_profile.cpp
  actions.cpp
  ageing.cpp
  bytecontainer.cpp
  calculations.cpp
  checksums.cpp
  conditionals.cpp
  context.cpp
  control_action.cpp
  counters.cpp
  crc_map.cpp
  debugger.cpp
  deparser.cpp
  dev_mgr.cpp
  dev_mgr_bmi.cpp
  dev_mgr_packet_in.cpp
  enums.cpp
  event_logger.cpp
  expressions.cpp
  extern.cpp
  fields.cpp
  headers.cpp
  header_unions.cpp
  learning.cpp
  lookup_structures.cpp
  logger.cpp
  match_error_codes.cpp
  match_tables.cpp
  match_units.cpp
  md5.c
  meters.cpp
  options_parse.cpp
  P4Objects.cpp
  packet.cpp
  parser.cpp
  parser_error.cpp
  pcap_file.cpp
  periodic_task.cpp
  phv.cpp
  phv_source.cpp
  pipeline.cpp
  port_monitor.cpp
  simple_pre.cpp
  simple_pre_lag.cpp
  source_info.cpp
  stacks.cpp
  stateful.cpp
  switch.cpp
  tables.cpp
  target_parser.cpp
  transport.cpp
  transport_nn.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/version.cpp
  xxhash.c
  core/primitives.cpp
)

# Add coverage flags if enabled
if(ENABLE_COVERAGE)
  target_compile_options(bmsim PRIVATE ${COVERAGE_FLAGS})
endif()

# Set include directories
target_include_directories(bmsim PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Link libraries
target_link_libraries(bmsim PUBLIC
  ${CMAKE_THREAD_LIBS_INIT}
  ${GMP_LIBRARY}
  ${PCAP_LIBRARY}
  Boost::thread
)

if(WITH_NANOMSG)
  target_link_libraries(bmsim PUBLIC ${NANOMSG_LIBRARY})
endif()
