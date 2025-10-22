# Tests to compile
set(TESTS
  test_parser_deparser_1
  test_exact_match_1
  test_LPM_match_1
  test_ternary_match_1
)

# Common files to include in all tests
set(COMMON_SRCS
  ../bmi_stubs.c
  stress_utils.cpp
)

foreach(target ${TESTS})

  add_executable(${target}
    ${target}.cpp
    ${COMMON_SRCS}
  )
  target_link_libraries(${target}
    gtest
    bmapps
    bmsim
    jsoncpp
    ${THRIFT_LIBRARIES}
    Boost::filesystem
    Boost::program_options
  )
  target_compile_definitions(${target} PUBLIC TESTDATADIR="${CMAKE_CURRENT_SOURCE_DIR}/testdata")
  add_test(NAME stress_tests/${target} COMMAND ${target})

endforeach()
