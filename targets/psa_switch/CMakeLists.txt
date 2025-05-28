# FIXME: handle the tests directory

set(THRIFT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/thrift/psa_switch.thrift")

# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

# Create psaswitch library
add_library(psaswitch STATIC
  psa_switch.cpp
  primitives.cpp
  externs/psa_counter.cpp
  externs/psa_meter.cpp
  externs/psa_random.cpp
  externs/psa_internet_checksum.cpp
  externs/psa_hash.cpp
)

target_link_libraries(psaswitch
  bmsim
  bflpmtrie
  bmi
  jsoncpp
  Boost::system
  Boost::program_options
  Boost::filesystem
  ${THRIFT_LIBRARIES}
)

# Create psa_switch executable
add_executable(psa_switch
  main.cpp
)

target_link_libraries(psa_switch
  bmruntime
  runtimestubs
  psaswitch
)

# Install psa_switch executable
install(TARGETS psa_switch
  RUNTIME DESTINATION bin
)


if(WITH_THRIFT)

  # FIXME: need to handle python part from makefile

  set(THRIFT_GEN_CPP_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp)
  set(THRIFT_GEN_PY_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-py)

  set(THRIFT_CPP_FILES
    ${THRIFT_GEN_CPP_DIR}/bm/psa_switch_constants.cpp
    ${THRIFT_GEN_CPP_DIR}/bm/psa_switch_constants.h
    ${THRIFT_GEN_CPP_DIR}/bm/psa_switch_types.cpp
    ${THRIFT_GEN_CPP_DIR}/bm/psa_switch_types.h
    ${THRIFT_GEN_CPP_DIR}/bm/PsaSwitch.cpp
    ${THRIFT_GEN_CPP_DIR}/bm/PsaSwitch.h
  )

  add_custom_command(
    OUTPUT ${THRIFT_CPP_FILES}
    COMMAND mkdir -p ${THRIFT_GEN_CPP_DIR}/bm
    COMMAND ${THRIFT_COMPILER} -out ${THRIFT_GEN_CPP_DIR}/bm --gen cpp -r ${THRIFT_FILE}
    COMMAND ${THRIFT_COMPILER} --gen py -r -o ${CMAKE_CURRENT_BINARY_DIR} ${THRIFT_FILE}
    DEPENDS ${THRIFT_FILE}
    COMMENT "Generating Thrift files for psa_switch"
  )

  target_include_directories(psaswitch PUBLIC ${THRIFT_GEN_CPP_DIR})
  target_sources(psaswitch PUBLIC ${THRIFT_CPP_FILES})
  target_sources(psaswitch PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/thrift/src/PsaSwitch_server.cpp)
endif()
