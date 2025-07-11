# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# Add PI support if enabled
if(WITH_PI)
  add_definitions(-DWITH_PI)
  include_directories(${CMAKE_SOURCE_DIR}/PI)
  set(PI_LIB bmpi)
else()
  set(PI_LIB "")
endif()

# Create simpleswitch library
add_library(simpleswitch STATIC
  simple_switch.cpp
  primitives.cpp
)

target_link_libraries(simpleswitch
  bmsim
  bmi
  jsoncpp
  Boost::system
  Boost::program_options
  Boost::filesystem
  ${THRIFT_LIBRARIES}
)

# Create simpleswitch_runner library
add_library(simpleswitch_runner SHARED
  runner.cpp
)

target_link_libraries(simpleswitch_runner
  simpleswitch
  ${PI_LIB}
)

# Install headers
install(FILES bm/simple_switch/runner.h
  DESTINATION include/bm/simple_switch
)

# Add Thrift support if enabled
if(WITH_THRIFT)
  # Find Thrift
  find_package(Thrift REQUIRED)
  
  # Include Thrift directories
  include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/thrift/src
    ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp
  )
  
  # Generate Thrift files
  set(THRIFT_IDL ${CMAKE_CURRENT_SOURCE_DIR}/thrift/simple_switch.thrift)
  set(THRIFT_PY_FILES
    ${CMAKE_CURRENT_BINARY_DIR}/gen-py/sswitch_runtime/constants.py
    ${CMAKE_CURRENT_BINARY_DIR}/gen-py/sswitch_runtime/__init__.py
    ${CMAKE_CURRENT_BINARY_DIR}/gen-py/sswitch_runtime/SimpleSwitch.py
    ${CMAKE_CURRENT_BINARY_DIR}/gen-py/sswitch_runtime/ttypes.py
  )
  generate_thrift(${THRIFT_IDL} THRIFT_CPP_FILES THRIFT_PY_NAMESPACE THRIFT_PY_FILES
    GEN_CPP_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp/bm
  )
  
  add_custom_target(genthrift_simpleswitch DEPENDS ${THRIFT_CPP_FILES})
  
  # Create simpleswitch_thrift library
  add_library(simpleswitch_thrift STATIC
    ${THRIFT_CPP_FILES}
  )
  add_dependencies(simpleswitch_thrift genthrift_simpleswitch)
  
  # Add Thrift server to simpleswitch library
  target_sources(simpleswitch PRIVATE
    thrift/src/SimpleSwitch_server.cpp
  )
  add_dependencies(simpleswitch genthrift_simpleswitch)
  
  # Create simple_switch executable
  add_executable(simple_switch
    main.cpp
  )
  
  target_link_libraries(simple_switch
    bmruntime
    runtimestubs
    simpleswitch
    simpleswitch_thrift
  )
  
  if(ENABLE_MODULES)
    target_link_options(simple_switch PRIVATE -rdynamic)
  endif()
  
  # Install simple_switch executable
  install(TARGETS simple_switch
    RUNTIME DESTINATION bin
  )
  
  # Install Thrift headers
  install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp/bm/simple_switch_constants.h
    ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp/bm/SimpleSwitch.h
    ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp/bm/simple_switch_types.h
    DESTINATION include/bm
  )
  
  # Install Python modules
  install(FILES ${THRIFT_PY_FILES}
    DESTINATION ${PY_SITE_PKG_DIR}/${THRIFT_PY_NAMESPACE}
  )
  
  # Install Python CLI
  install(FILES sswitch_CLI.py
    DESTINATION ${PY_SITE_PKG_DIR}
  )
  
  # Configure and install simple_switch_CLI script
  set(pythondir "${CMAKE_INSTALL_PREFIX}/${PY_SITE_PKG_DIR}")
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/simple_switch_CLI.in
    ${CMAKE_CURRENT_BINARY_DIR}/simple_switch_CLI
    @ONLY
  )
  
  if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.19")
    file(CHMOD ${CMAKE_CURRENT_BINARY_DIR}/simple_switch_CLI
      PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                  GROUP_READ GROUP_EXECUTE
                  WORLD_READ WORLD_EXECUTE
    )
  else()
    add_custom_target(
      make_simple_switch_CLI_executable
      COMMAND ${CMAKE_COMMAND} -E chmod +x ${CMAKE_CURRENT_BINARY_DIR}/simple_switch_CLI
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/simple_switch_CLI
      COMMENT "Making simple_switch_CLI executable"
    )
  endif()
  
  install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/simple_switch_CLI
    DESTINATION bin
  )

  # Install libraries
  install(TARGETS simpleswitch_thrift
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
  )
endif()

# Add tests if nanomsg is enabled
if(WITH_NANOMSG)
  add_subdirectory(tests)
endif()

# Install libraries
install(TARGETS simpleswitch simpleswitch_runner
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
