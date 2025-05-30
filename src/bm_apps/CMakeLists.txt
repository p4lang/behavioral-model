# Add library
add_library(bmapps STATIC
  notifications.cpp
  packet_pipe.cpp
)

# Set include directories
target_include_directories(bmapps PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link libraries
target_link_libraries(bmapps
  bmsim
  ${NANOMSG_LIBRARY}
)

# Add coverage flags if enabled
if(ENABLE_COVERAGE)
  target_compile_options(bmapps PRIVATE ${COVERAGE_FLAGS})
endif()
