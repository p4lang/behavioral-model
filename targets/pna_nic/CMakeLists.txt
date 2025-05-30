# FIXME: handle the tests directory

set(THRIFT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/thrift/pna_nic.thrift")

# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

# Create pnanic library
add_library(pnanic STATIC
  pna_nic.cpp
  primitives.cpp
  externs/pna_counter.cpp
  externs/pna_meter.cpp
  externs/pna_random.cpp
  externs/pna_internet_checksum.cpp
  externs/pna_hash.cpp
)

target_link_libraries(pnanic
  bmsim
  bflpmtrie
  bmi
  jsoncpp
  Boost::system
  Boost::program_options
  Boost::filesystem
  ${THRIFT_LIBRARIES}
)

if(WITH_THRIFT)
  # Create pna_nic executable
  add_executable(pna_nic
    main.cpp
  )

  target_link_libraries(pna_nic
    bmruntime
    runtimestubs
    pnanic
    pnanic_thrift
  )

  # Install pna_nic executable
  install(TARGETS pna_nic
    RUNTIME DESTINATION bin
  )

  # FIXME: need to handle python part from makefile

  set(THRIFT_GEN_CPP_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp)
  set(THRIFT_GEN_PY_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-py)

  set(THRIFT_CPP_FILES
    ${THRIFT_GEN_CPP_DIR}/bm/pna_nic_constants.cpp
    ${THRIFT_GEN_CPP_DIR}/bm/pna_nic_constants.h
    ${THRIFT_GEN_CPP_DIR}/bm/pna_nic_types.cpp
    ${THRIFT_GEN_CPP_DIR}/bm/pna_nic_types.h
    ${THRIFT_GEN_CPP_DIR}/bm/PnaNic.cpp
    ${THRIFT_GEN_CPP_DIR}/bm/PnaNic.h
  )

  add_custom_command(
    OUTPUT ${THRIFT_CPP_FILES}
    COMMAND mkdir -p ${THRIFT_GEN_CPP_DIR}/bm
    COMMAND ${THRIFT_COMPILER} -out ${THRIFT_GEN_CPP_DIR}/bm --gen cpp -r ${THRIFT_FILE}
    COMMAND ${THRIFT_COMPILER} --gen py -r -o ${CMAKE_CURRENT_BINARY_DIR} ${THRIFT_FILE}
    # FIXME: ported from Makefile -- some thrift versions don't create all expected outputs
    COMMAND touch ${THRIFT_CPP_FILES}
    DEPENDS ${THRIFT_FILE}
    COMMENT "Generating Thrift files for pna_nic"
  )
  add_custom_target(genthrift_pnanic DEPENDS ${THRIFT_CPP_FILES})

  add_library(pnanic_thrift STATIC
    ${THRIFT_CPP_FILES}
  )
  target_include_directories(pnanic_thrift PUBLIC ${THRIFT_GEN_CPP_DIR})
  add_dependencies(pnanic_thrift genthrift_pnanic)

  target_include_directories(pnanic PUBLIC ${THRIFT_GEN_CPP_DIR})
  #target_sources(pnanic PUBLIC ${THRIFT_CPP_FILES})
  target_sources(pnanic PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/thrift/src/PnaNic_server.cpp)
  add_dependencies(pnanic genthrift_pnanic)
endif()
