if(WITH_NANOMSG)
  add_subdirectory(tests)
endif()

set(THRIFT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/thrift/pna_nic.thrift")

# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
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

  generate_thrift(${THRIFT_FILE} THRIFT_CPP_FILES GEN_CPP_DIR ${THRIFT_GEN_CPP_DIR}/bm)

  add_custom_target(genthrift_pnanic DEPENDS ${THRIFT_CPP_FILES})

  add_library(pnanic_thrift STATIC
    ${THRIFT_CPP_FILES}
  )
  target_include_directories(pnanic_thrift PUBLIC ${THRIFT_GEN_CPP_DIR})
  add_dependencies(pnanic_thrift genthrift_pnanic)

  target_include_directories(pnanic PUBLIC ${THRIFT_GEN_CPP_DIR})
  target_sources(pnanic PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/thrift/src/PnaNic_server.cpp)
  add_dependencies(pnanic genthrift_pnanic)
endif()
