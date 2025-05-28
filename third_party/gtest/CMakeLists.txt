# Create gtest library
add_library(gtest STATIC
  src/gtest-all.cc
)

# Set include directories
target_include_directories(gtest PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}
)
