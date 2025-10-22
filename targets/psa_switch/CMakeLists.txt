if(WITH_NANOMSG)
  add_subdirectory(tests)
endif()

set(THRIFT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/thrift/psa_switch.thrift")

# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
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
  bmi
  jsoncpp
  Boost::program_options
  Boost::filesystem
  ${THRIFT_LIBRARIES}
)

if(WITH_THRIFT)
  # Create psa_switch executable
  add_executable(psa_switch
    main.cpp
  )

  target_link_libraries(psa_switch
    bmruntime
    runtimestubs
    psaswitch
    psaswitch_thrift
  )

  # Install psa_switch executable
  install(TARGETS psa_switch
    RUNTIME DESTINATION bin
  )


  # Generate and compile trift files
  set(THRIFT_GEN_CPP_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp)

  generate_thrift(${THRIFT_FILE} THRIFT_CPP_FILES THRIFT_PY_NAMESPACE THRIFT_PY_FILES
    GEN_CPP_DIR ${THRIFT_GEN_CPP_DIR}/bm
  )

  add_custom_target(genthrift_psaswitch DEPENDS ${THRIFT_CPP_FILES})

  add_library(psaswitch_thrift STATIC
    ${THRIFT_CPP_FILES}
  )
  target_include_directories(psaswitch_thrift PUBLIC ${THRIFT_GEN_CPP_DIR})
  add_dependencies(psaswitch_thrift genthrift_psaswitch)

  target_include_directories(psaswitch PUBLIC ${THRIFT_GEN_CPP_DIR})
  target_sources(psaswitch PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/thrift/src/PsaSwitch_server.cpp)
  add_dependencies(psaswitch genthrift_psaswitch)

  # Install Thrift headers
  install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp/bm/psa_switch_constants.h
    ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp/bm/PsaSwitch.h
    ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp/bm/psa_switch_types.h
    DESTINATION include/bm
  )

  # Install Python modules
  install(FILES ${THRIFT_PY_FILES}
    DESTINATION ${PY_SITE_PKG_DIR}/pswitch_runtime
  )

  # Install Python CLI
  install(FILES pswitch_CLI.py
    DESTINATION ${PY_SITE_PKG_DIR}
  )

  # Configure and install psa_switch_CLI script
  set(pythondir "${CMAKE_INSTALL_PREFIX}/${PY_SITE_PKG_DIR}")
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/psa_switch_CLI.in
    ${CMAKE_CURRENT_BINARY_DIR}/psa_switch_CLI
    @ONLY
  )

  if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.19")
    file(CHMOD ${CMAKE_CURRENT_BINARY_DIR}/psa_switch_CLI
      PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                  GROUP_READ GROUP_EXECUTE
                  WORLD_READ WORLD_EXECUTE
    )
  else()
    add_custom_target(
      make_psa_switch_CLI_executable
      COMMAND ${CMAKE_COMMAND} -E chmod +x ${CMAKE_CURRENT_BINARY_DIR}/psa_switch_CLI
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/psa_switch_CLI
      COMMENT "Making psa_switch_CLI executable"
    )
  endif()

  install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/psa_switch_CLI
    DESTINATION bin
  )

  # Install libraries
  install(TARGETS psaswitch_thrift
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
  )
endif()
