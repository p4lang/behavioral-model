cmake_minimum_required(VERSION 3.10)

# Include all necessary files for macros
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckIncludeFileCXX)

# Add cmake modules path
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Extract version from VERSION file
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" BM_VERSION)
string(STRIP "${BM_VERSION}" BM_VERSION)

project(behavioral-model
  VERSION ${BM_VERSION}
  DESCRIPTION "Behavioral Model (BMv2) - P4 software switch"
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
option(WITH_TARGETS "Build targets" ON)
option(WITH_STRESS_TESTS "Include stress tests" OFF)
option(ENABLE_DEBUGGER "Enable bmv2 remote debugger" OFF)
option(ENABLE_COVERAGE "Enable code coverage tracking" OFF)
option(ENABLE_LOGGING_MACROS "Enable compile time debug and trace logging macros" ON)
option(ENABLE_ELOGGER "Enable nanomsg event logger" ON)
option(ENABLE_MODULES "Allow loading third-party modules at runtime" OFF)
option(ENABLE_UNDETERMINISTIC_TESTS "Run undeterministic tests (e.g. queueing) when running tests" ON)
option(ENABLE_WERROR "Make all compiler warnings fatal" OFF)
option(ENABLE_WP4_16_STACKS "Implement stacks strictly as per the P4_16 specification" ON)

# Set compiler flags
add_compile_options(-Wall -Wextra)
if(ENABLE_WERROR)
  # FIXME: remoe the -Wno-error=sign-compare when source is cleaned
  add_compile_options(-Werror -Wno-error=sign-compare)
endif()

if(ENABLE_COVERAGE)
  add_compile_options(-coverage)
  link_libraries(gcov)
endif()

# Seeing build failures that are fixed by including atomic when compiling with clang
# FIXME: understand why this is -- wasn't required in autoconf build
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  link_libraries(${TEST_NAME}
    atomic
  )
endif()

# Make all code position-independent
# (FIXME: which files should be PIC?)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Define include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/jsoncpp/include
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/spdlog
)

# Find required packages
find_package(Threads REQUIRED)
find_package(Boost REQUIRED COMPONENTS thread program_options filesystem system)

# Check for header files
# FIXME: consider dropping BM_ prefix if autoconf support is dropped
set(C_HEADERS
  sys/stat.h sys/types.h unistd.h
)
foreach (hdr ${C_HEADERS})
  string(TOUPPER ${hdr} hdr_uc)
  string(REGEX REPLACE "[/.]" "_" hdr_uc ${hdr_uc})
  CHECK_INCLUDE_FILE(${hdr} BM_HAVE_${hdr_uc})
  if (NOT BM_HAVE_${hdr_uc})
    message(SEND_ERROR "Could not find include: ${hdr}")
  endif()
endforeach()

set(CXX_HEADERS
  algorithm array cassert cmath queue
  cstdio string sys/stat.h sys/types.h ctime tuple unistd.h unordered_map
  utility vector
)
foreach (hdr ${CXX_HEADERS})
  string(TOUPPER ${hdr} hdr_uc)
  CHECK_INCLUDE_FILE_CXX(${hdr} BM_HAVE_${hdr_uc})
  if (NOT BM_HAVE_${hdr_uc})
    message(SEND_ERROR "Could not find include: ${hdr}")
  endif()
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

if(ENABLE_MODULES)
  # Check for dlopen
  check_include_file(dlfcn.h HAVE_DLFCN_H)
  if(HAVE_DLFCN_H)
    add_definitions(-DHAVE_DLOPEN -DENABLE_MODULES)
    check_symbol_exists(dlopen "dlfcn.h" HAVE_DLOPEN)
  else()
    message(FATAL_ERROR "Cannot enable modules without dlfcn.h")
  endif()
endif()

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
