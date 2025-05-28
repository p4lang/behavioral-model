# Translate some variables for use by config.h
if (WITH_NANOMSG AND ENABLE_ELOGGER)
  set (BM_ELOG_ON 1)
endif()
if (HAVE_DLFCN_H)
  set (BM_HAVE_DLFCN_H 1)
endif()
if (HAVE_DLOPEN)
  set (BM_HAVE_DLOPEN 1)
endif()
if (HAVE_THRIFT_STDCXX_H)
  set (BM_HAVE_THRIFT_STDCXX_H 1)
endif()
if (WITH_NANOMSG AND ENABLE_DEBUGGER)
  set(BM_DEBUG_ON 1)
endif()
if (ENABLE_LOGGING_MACROS)
  set(BM_LOG_DEBUG_ON 1)
  set(BM_LOG_TRACE_ON 1)
endif()
if (WITH_NANOMSG)
  set(BM_NANOMSG_ON 1)
endif()
if (WITH_THRIFT)
  set(BM_THRIFT_ON 1)
endif()
if(ENABLE_WP4_16_STACKS)
  set(BM_WP4_16_STACKS 1)
endif()
# FIXME: BM_ENABLE_MODULES translation here
set (BM_THRIFT_VERSION ${THRIFT_VERSION_NUMBER})

# Configure config.h
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/bm/config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/bm/config.h
)

# Install headers
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/bm/config.h
  DESTINATION include/bm
)

# Install bm_sim headers
file(GLOB BM_SIM_HEADERS "bm/bm_sim/*.h")
install(FILES ${BM_SIM_HEADERS}
  DESTINATION include/bm/bm_sim
)

# Install bm_sim/core headers
file(GLOB BM_SIM_CORE_HEADERS "bm/bm_sim/core/*.h")
install(FILES ${BM_SIM_CORE_HEADERS}
  DESTINATION include/bm/bm_sim/core
)

# Install bm_grpc headers
file(GLOB BM_GRPC_HEADERS "bm/bm_grpc/*.h")
install(FILES ${BM_GRPC_HEADERS}
  DESTINATION include/bm/bm_grpc
)

# Install thrift headers if enabled
if(WITH_THRIFT)
  file(GLOB BM_RUNTIME_HEADERS "bm/bm_runtime/*.h")
  install(FILES ${BM_RUNTIME_HEADERS}
    DESTINATION include/bm/bm_runtime
  )
  
  file(GLOB THRIFT_HEADERS "bm/thrift/*.h")
  install(FILES ${THRIFT_HEADERS}
    DESTINATION include/bm/thrift
  )
endif()

# Install bm_apps headers if nanomsg is enabled
if(WITH_NANOMSG)
  file(GLOB BM_APPS_HEADERS "bm/bm_apps/*.h")
  install(FILES ${BM_APPS_HEADERS}
    DESTINATION include/bm/bm_apps
  )
endif()
