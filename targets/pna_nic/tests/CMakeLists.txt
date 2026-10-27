# SPDX-FileCopyrightText: 2025 Glen Gibb
#
# SPDX-License-Identifier: Apache-2.0

# Define test data directory
add_definitions(-DTESTDATADIR="${CMAKE_CURRENT_SOURCE_DIR}/testdata")

add_executable(test_parse_pna
  main.cpp
  test_parse_pna.cpp
)

target_link_libraries(test_parse_pna
  pnanic
  gtest
  test_utils
  bmapps
)

target_include_directories(test_parse_pna PRIVATE
  ..
  ${CMAKE_SOURCE_DIR}/targets/test_utils
)

add_test(NAME pna_nic/test_parse_pna COMMAND test_parse_pna)

add_executable(pna_nic_test_meter_counter_bounds
  main.cpp
  test_meter_counter_bounds.cpp
)

target_link_libraries(pna_nic_test_meter_counter_bounds
  pnanic
  gtest
  bmapps
)

target_include_directories(pna_nic_test_meter_counter_bounds PRIVATE
  ..
)

set_target_properties(pna_nic_test_meter_counter_bounds PROPERTIES
  OUTPUT_NAME test_meter_counter_bounds
)

add_test(NAME pna_nic/test_meter_counter_bounds
  COMMAND pna_nic_test_meter_counter_bounds)

# FIXME: do we want the test_all target?
