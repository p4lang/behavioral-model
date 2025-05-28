# Add library
add_library(bmruntime STATIC
  server.cpp
  SimplePreLAG_server.cpp
  SimplePre_server.cpp
  Standard_server.cpp
)

# Set include directories
target_include_directories(bmruntime PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${THRIFT_GEN_CPP_DIR}
)

# Link libraries
target_link_libraries(bmruntime
  bmsim
  ${THRIFT_LIBRARIES}
)

# Add coverage flags if enabled
if(ENABLE_COVERAGE)
  target_compile_options(bmruntime PRIVATE ${COVERAGE_FLAGS})
endif()
