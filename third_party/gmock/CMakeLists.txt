# Create gtest library
add_library(gmock STATIC
  src/gmock-all.cc
)

# Set include directories
target_include_directories(gmock PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link in gtest
target_link_libraries(gmock gtest)
