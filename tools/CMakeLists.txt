# Set Python scripts
set(PYTHON_SCRIPTS "")
set(BIN_SCRIPTS "")

# Add Thrift-related scripts
if(WITH_THRIFT)
  list(APPEND PYTHON_SCRIPTS
    bmpy_utils.py
    runtime_CLI.py
  )

  # Configure bm_CLI script
  set(pythondir "${CMAKE_INSTALL_PREFIX}/${PY_SITE_PKG_DIR}")
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/bm_CLI.in
    ${CMAKE_CURRENT_BINARY_DIR}/bm_CLI
    @ONLY
  )

  list(APPEND BIN_SCRIPTS
    ${CMAKE_CURRENT_BINARY_DIR}/bm_CLI
  )
endif()

# Add Nanomsg-related scripts
if(WITH_NANOMSG)
  list(APPEND PYTHON_SCRIPTS
    p4dbg.py
    nanomsg_client.py
  )

  # Configure bm_p4dbg script
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/bm_p4dbg.in
    ${CMAKE_CURRENT_BINARY_DIR}/bm_p4dbg
    @ONLY
  )

  # Configure bm_nanomsg_events script
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/bm_nanomsg_events.in
    ${CMAKE_CURRENT_BINARY_DIR}/bm_nanomsg_events
    @ONLY
  )

  list(APPEND BIN_SCRIPTS
    ${CMAKE_CURRENT_BINARY_DIR}/bm_p4dbg
    ${CMAKE_CURRENT_BINARY_DIR}/bm_nanomsg_events
  )
endif()

# Make scripts executable
foreach(script ${BIN_SCRIPTS})
  if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.19")
    file(CHMOD ${script}
      PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                  GROUP_READ GROUP_EXECUTE
                  WORLD_READ WORLD_EXECUTE
    )
  else()
    get_filename_component(script_no_dir ${script} NAME_WE)
    add_custom_target(
      make_${script_no_dir}_executable
      COMMAND ${CMAKE_COMMAND} -E chmod +x ${script}
      DEPENDS ${script}
      COMMENT "Making ${script} executable"
    )
  endif()
endforeach()

# Install Python scripts
install(FILES ${PYTHON_SCRIPTS}
  DESTINATION ${PY_SITE_PKG_DIR}
)

# Install binary scripts
install(PROGRAMS ${BIN_SCRIPTS}
  DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/
)

# Install utility scripts
install(FILES
  run_valgrind.sh
  veth_setup.sh
  veth_teardown.sh
  DESTINATION ${CMAKE_INSTALL_PREFIX}/share/behavioral-model/
)
