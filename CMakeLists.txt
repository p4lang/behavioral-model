cmake_minimum_required(VERSION 3.10)

# Use ccache if it is installed
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    MESSAGE(STATUS "Enabling ccache")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

# Add cmake modules path
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Include necessary files for macros
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckIncludeFileCXX)
include(GenerateThrift)

# Extract version from VERSION file
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" BM_VERSION)
string(STRIP "${BM_VERSION}" BM_VERSION)

# Define the project
project(behavioral-model
  VERSION ${BM_VERSION}
  DESCRIPTION "Behavioral Model (BMv2) - P4 software switch"
  HOMEPAGE_URL "https://github.com/p4lang/behavioral-model"
  LANGUAGES CXX C
)

# Enable testing
include(CTest)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(WITH_NANOMSG "Support generating Nanomsg events" ON)
option(WITH_THRIFT "Build Thrift RPC service" ON)
option(WITH_PI "Build PI implementation for bmv2" OFF)
option(WITH_PDFIXED "Build pdfixed for bmv2" OFF)
option(WITH_TARGETS "Build targets (simple_switch, psa_switch, ...)" ON)
option(WITH_STRESS_TESTS "Include stress tests" OFF)
option(ENABLE_DEBUGGER "Enable bmv2 remote debugger" OFF)
option(ENABLE_COVERAGE "Enable code coverage tracking" OFF)
option(ENABLE_LOGGING_MACROS "Enable compile time debug and trace logging macros" ON)
option(ENABLE_ELOGGER "Enable nanomsg event logger" ON)
option(ENABLE_MODULES "Allow loading third-party modules at runtime" ON)
option(REQUIRE_MODULES "Require support for loading third-party modules at runtime" OFF)
option(ENABLE_UNDETERMINISTIC_TESTS "Run undeterministic tests (e.g. queueing) when running tests" ON)
option(ENABLE_WERROR "Make all compiler warnings fatal" OFF)
option(ENABLE_WP4_16_STACKS "Implement stacks strictly as per the P4_16 specification" ON)

# Set compiler flags
add_compile_options(-Wall -Wextra)
if(ENABLE_WERROR)
  add_compile_options(-Werror)
endif()

if(ENABLE_COVERAGE)
  add_compile_options(-coverage)
  link_libraries(gcov)
endif()

# clang builds were failing due to missing atomic library
# FIXME: understand why this is -- wasn't required in autoconf build
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  link_libraries(${TEST_NAME}
    atomic
  )
endif()

# Make all code position-independent
# FIXME: which files should be PIC?
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Define include directories
# FIXME: consider moving these to specific targets?
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/jsoncpp/include
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/spdlog
)

# Find required packages
find_package(Threads REQUIRED)
find_package(Boost REQUIRED COMPONENTS thread program_options filesystem system)

# Check for the presence of an include file and report an error if not found
#
# Usage: require_include(HDR <C/CXX>)
function(REQUIRE_INCLUDE HDR)
  string(TOUPPER ${HDR} HDR_UC)
  string(REGEX REPLACE "[/.]" "_" HDR_UC ${HDR_UC})
  if(${LANGUAGE_C})
    check_include_file(${HDR} BM_HAVE_${HDR_UC})
  else()
    check_include_file_cxx(${HDR} BM_HAVE_${HDR_UC})
  endif()
  if (NOT BM_HAVE_${HDR_UC})
    message(SEND_ERROR "Could not find include: ${HDR}")
  endif()
endfunction()

# Check for necessary header files
# Replicates checks performed by autoconf
# FIXME: consider dropping BM_ prefix if autoconf support is dropped
set(C_HEADERS
  sys/stat.h sys/types.h unistd.h
)
set(CXX_HEADERS
  algorithm array cassert cmath queue
  cstdio string sys/stat.h sys/types.h ctime tuple unistd.h unordered_map
  utility vector
)
foreach (hdr ${C_HEADERS})
  require_include(${hdr} C)
endforeach()
foreach (hdr ${CXX_HEADERS})
  require_include(${hdr} CXX)
endforeach()

# Check for libraries
find_library(GMP_LIBRARY gmp REQUIRED)
find_library(PCAP_LIBRARY pcap REQUIRED)

if(WITH_NANOMSG)
  find_library(NANOMSG_LIBRARY nanomsg REQUIRED)
  add_definitions(-DNANOMSG_ON)

  if(ENABLE_ELOGGER)
    add_definitions(-DELOG_ON)
  endif()

  if(ENABLE_DEBUGGER)
    add_definitions(-DDEBUG_ON)
  endif()
endif()

if(ENABLE_LOGGING_MACROS)
  add_definitions(-DLOG_DEBUG_ON -DLOG_TRACE_ON)
endif()

if(ENABLE_WP4_16_STACKS)
  add_definitions(-DWP4_16_STACKS)
endif()

if(WITH_THRIFT)
  # Find Thrift
  find_package(Thrift REQUIRED)
  add_definitions(-DTHRIFT_ON)
endif()

if(WITH_PI)
  # Find Protobuf and gRPC
  find_package(Protobuf REQUIRED)
  find_package(gRPC REQUIRED)

  # Verify that PI headers are present
  check_include_files("PI/pi.h;PI/target/pi_imp.h;PI/p4info.h"
    HAVE_PI_HEADERS LANGUAGE CXX)
  if (NOT HAVE_PI_HEADERS)
    set(PI_URL "https://github.com/p4lang/PI/")
    message(SEND_ERROR "Cannot find PI headers, did you install ${PI_URL}")
  endif()
endif()

if(REQUIRE_MODULES AND NOT ENABLE_MODULES)
  message(FATAL_ERROR
    "Incompatible settings for ENABLE_MODULES (OFF) and REQUIRE_MODULES (ON): "
    "REQUIRE_MODULES requires ENABLE_MODULES")
endif()

if(ENABLE_MODULES)
  # Check if dlopen is available
  # Set ENABLE_MODULES to OFF if it's not available
  check_include_file(dlfcn.h HAVE_DLFCN_H)
  if(HAVE_DLFCN_H)
    include(CheckSymbolExists)
    set(CMAKE_REQUIRED_LIBRARIES "dl")
    check_symbol_exists(dlopen "dlfcn.h" HAVE_DLOPEN)
    unset(CMAKE_REQUIRED_LIBRARIES)
    if(HAVE_DLOPEN)
      add_definitions(-DHAVE_DLOPEN -DENABLE_MODULES)
    else()
      set(ENABLE_MODULES OFF)
    endif()
  endif()

  if(REQUIRE_MODULES AND NOT HAVE_DLOPEN)
    message(FATAL_ERROR "Cannot enable modules without dlopen()")
  endif()
endif()

# Identify python installation directory
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(PY_SITE_PKG_DIR "lib/python${Python3_VERSION_MAJOR}.${Python3_VERSION_MINOR}/site-packages")

# Add subdirectories
if(WITH_THRIFT)
  add_subdirectory(thrift_src)
endif()

add_subdirectory(third_party)
add_subdirectory(src)
add_subdirectory(include)

if(WITH_THRIFT AND WITH_TARGETS)
  add_subdirectory(tests)
endif()

if(WITH_PI)
  add_subdirectory(PI)
  add_subdirectory(services)
endif()

if(WITH_TARGETS)
  add_subdirectory(targets)
endif()

add_subdirectory(tools)

if(WITH_PDFIXED)
  add_subdirectory(pdfixed)
endif()

# Installation rules
install(FILES LICENSE README.md
  DESTINATION share/doc/behavioral-model)

# Print configuration summary
message(STATUS "Configuration summary:")
message(STATUS "  Version: ${BM_VERSION}")
message(STATUS "  Coverage enabled: ${ENABLE_COVERAGE}")
message(STATUS "  Logging macros enabled: ${ENABLE_LOGGING_MACROS}")
message(STATUS "  With Nanomsg: ${WITH_NANOMSG}")
message(STATUS "  Event logger enabled: ${ENABLE_ELOGGER}")
message(STATUS "  Debugger enabled: ${ENABLE_DEBUGGER}")
message(STATUS "  With Thrift: ${WITH_THRIFT}")
message(STATUS "  With pdfixed: ${WITH_PDFIXED}")
message(STATUS "  With PI: ${WITH_PI}")
