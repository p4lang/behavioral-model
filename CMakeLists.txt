cmake_minimum_required(VERSION 3.10)
project(behavioral-model)

# Set C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(WITH_PDFIXED "Build with PDFixed support" ON)
option(WITH_PI "Build with PI support" ON)
option(WITH_THRIFT "Build with Thrift support" ON)
option(WITH_NANOMSG "Build with Nanomsg support" ON)
option(WITH_STRESS_TESTS "Build with stress tests" OFF)
option(ENABLE_DEBUGGER "Enable debugger support" OFF)
option(ENABLE_WERROR "Treat warnings as errors" OFF)
option(ENABLE_COVERAGE "Enable coverage reporting" OFF)

# Include cmake modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Add subdirectories
add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(third_party)
add_subdirectory(targets)

if(WITH_THRIFT)
  add_subdirectory(thrift_src)
endif()

# Add check target
add_custom_target(check
  COMMAND ctest --output-on-failure
  COMMENT "Running tests..."
)
