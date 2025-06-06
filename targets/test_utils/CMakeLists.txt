# Create test_utils library
add_library(test_utils STATIC
  server.cpp
)

# Set include directories
target_include_directories(test_utils PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link libraries
target_link_libraries(test_utils PUBLIC
  bmsim
  ${CMAKE_THREAD_LIBS_INIT}
)
