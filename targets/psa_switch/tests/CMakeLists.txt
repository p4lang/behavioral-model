# Define test data directory
add_definitions(-DTESTDATADIR="${CMAKE_CURRENT_SOURCE_DIR}/testdata")

set(COMMON_SRCS main.cpp)
set(TESTS test_internet_checksum test_hash)
foreach(TEST_NAME ${TESTS})
  add_executable(${TEST_NAME}
    ${COMMON_SRCS}
    ${TEST_NAME}.cpp
  )

  target_link_libraries(${TEST_NAME}
    psaswitch
    gtest
    bmapps
    Boost::filesystem
  )
  if(WITH_THRIFT)
    target_link_libraries(${TEST_NAME}
      psaswitch_thrift
    )
  endif()

  target_include_directories(${TEST_NAME} PRIVATE
    ..
  )

  add_test(NAME psa_switch/${TEST_NAME} COMMAND ${TEST_NAME})
endforeach()

add_executable(psa_switch_test_all
  ${COMMON_SRCS}
  test_internet_checksum.cpp
  test_hash.cpp
)

target_link_libraries(psa_switch_test_all
  psaswitch
  #psaswitch_thrift
  gtest
  bmapps
  Boost::filesystem
)
if(WITH_THRIFT)
  target_link_libraries(psa_switch_test_all
    psaswitch_thrift
  )
endif()

target_include_directories(psa_switch_test_all PRIVATE
  ..
)

set_target_properties(psa_switch_test_all PROPERTIES
  OUTPUT_NAME test_all
)

add_test(NAME psa_switch/test_all COMMAND test_all
  CONFIGURATIONS test_all
)
