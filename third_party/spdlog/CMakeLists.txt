# spdlog is a header-only library, so we just need to install the headers
file(GLOB_RECURSE SPDLOG_HEADERS "bm/spdlog/*.h" "bm/spdlog/*.cc")

# Create interface library
add_library(spdlog INTERFACE)

# Set include directories
target_include_directories(spdlog INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# Install headers
# FIXME: evaluate whether this is needed
install(DIRECTORY bm/spdlog
  DESTINATION include/bm
  FILES_MATCHING PATTERN "*.h" PATTERN "*.cc"
)
