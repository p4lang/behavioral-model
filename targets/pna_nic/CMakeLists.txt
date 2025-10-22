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
  bmi
  jsoncpp
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

  # Generate and compile trift files
  set(THRIFT_GEN_CPP_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp)

  generate_thrift(${THRIFT_FILE} THRIFT_CPP_FILES THRIFT_PY_NAMESPACE THRIFT_PY_FILES
    GEN_CPP_DIR ${THRIFT_GEN_CPP_DIR}/bm
  )

  add_custom_target(genthrift_pnanic DEPENDS ${THRIFT_CPP_FILES})

  add_library(pnanic_thrift STATIC
    ${THRIFT_CPP_FILES}
  )
  target_include_directories(pnanic_thrift PUBLIC ${THRIFT_GEN_CPP_DIR})
  add_dependencies(pnanic_thrift genthrift_pnanic)

  target_include_directories(pnanic PUBLIC ${THRIFT_GEN_CPP_DIR})
  target_sources(pnanic PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/thrift/src/PnaNic_server.cpp)
  add_dependencies(pnanic genthrift_pnanic)

  # Install Thrift headers
  install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp/bm/pna_nic_constants.h
    ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp/bm/PnaNic.h
    ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp/bm/pna_nic_types.h
    DESTINATION include/bm
  )

  # Install Python modules
  install(FILES ${THRIFT_PY_FILES}
    DESTINATION ${PY_SITE_PKG_DIR}/pnic_runtime
  )

  # Install Python CLI
  install(FILES pnic_CLI.py
    DESTINATION ${PY_SITE_PKG_DIR}
  )

  # Configure and install pna_nic_CLI script
  set(pythondir "${CMAKE_INSTALL_PREFIX}/${PY_SITE_PKG_DIR}")
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pna_nic_CLI.in
    ${CMAKE_CURRENT_BINARY_DIR}/pna_nic_CLI
    @ONLY
  )

  if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.19")
    file(CHMOD ${CMAKE_CURRENT_BINARY_DIR}/pna_nic_CLI
      PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                  GROUP_READ GROUP_EXECUTE
                  WORLD_READ WORLD_EXECUTE
    )
  else()
    add_custom_target(
      make_pna_nic_CLI_executable
      COMMAND ${CMAKE_COMMAND} -E chmod +x ${CMAKE_CURRENT_BINARY_DIR}/pna_nic_CLI
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/pna_nic_CLI
      COMMENT "Making pna_nic_CLI executable"
    )
  endif()

  install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/pna_nic_CLI
    DESTINATION bin
  )

  # Install libraries
  install(TARGETS pnanic_thrift
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
  )
endif()
