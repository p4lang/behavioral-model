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
  bflpmtrie
  bmi
  jsoncpp
  Boost::system
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


  # FIXME: need to handle python part from makefile

  set(THRIFT_GEN_CPP_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp)

  generate_thrift(${THRIFT_FILE} THRIFT_CPP_FILES GEN_CPP_DIR ${THRIFT_GEN_CPP_DIR}/bm)

  add_custom_target(genthrift_psaswitch DEPENDS ${THRIFT_CPP_FILES})

  add_library(psaswitch_thrift STATIC
    ${THRIFT_CPP_FILES}
  )
  target_include_directories(psaswitch_thrift PUBLIC ${THRIFT_GEN_CPP_DIR})
  add_dependencies(psaswitch_thrift genthrift_psaswitch)

  target_include_directories(psaswitch PUBLIC ${THRIFT_GEN_CPP_DIR})
  target_sources(psaswitch PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/thrift/src/PsaSwitch_server.cpp)
  add_dependencies(psaswitch genthrift_psaswitch)
endif()
