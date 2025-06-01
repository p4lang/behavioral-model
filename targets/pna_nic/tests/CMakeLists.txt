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
  Boost::filesystem
)

target_include_directories(test_parse_pna PRIVATE
  ..
  ${CMAKE_SOURCE_DIR}/targets/test_utils
)

add_test(NAME pna_nic/test_parse_pna COMMAND test_parse_pna)

# FIXME: do we want the test_all target?
