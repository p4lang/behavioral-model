# - Find Thrift (a cross platform RPC lib/tool)
# This module defines
#  THRIFT_VERSION, version string of Thrift if found
#  THRIFT_INCLUDE_DIR, where to find Thrift headers
#  THRIFT_LIBRARIES, Thrift libraries
#  THRIFT_FOUND, If false, do not try to use Thrift

# prefer the thrift version supplied in THRIFT_HOME
find_path(THRIFT_INCLUDE_DIR
  NAMES
    thrift/Thrift.h
  HINTS
    ${THRIFT_HOME}/include
    /usr/local/include
    /opt/local/include
)

# prefer the thrift version supplied in THRIFT_HOME
find_library(THRIFT_LIBRARY
  NAMES
    thrift
  HINTS
    ${THRIFT_HOME}/lib
    /usr/local/lib
    /opt/local/lib
)

find_program(THRIFT_COMPILER
  NAMES
    thrift
  HINTS
    ${THRIFT_HOME}/bin
    /usr/local/bin
    /opt/local/bin
)

if (THRIFT_INCLUDE_DIR AND THRIFT_LIBRARY)
  set(THRIFT_FOUND TRUE)
  set(THRIFT_LIBRARIES ${THRIFT_LIBRARY})
  set(THRIFT_INCLUDE_DIRS ${THRIFT_INCLUDE_DIR})
  
  # Check for Thrift version
  file(STRINGS "${THRIFT_INCLUDE_DIR}/thrift/config.h" THRIFT_CONFIG_H REGEX "PACKAGE_VERSION")
  string(REGEX MATCH "\"[0-9]+\\.[0-9]+\\.[0-9]+\"" THRIFT_VERSION_STRING ${THRIFT_CONFIG_H})
  string(REGEX REPLACE "\"" "" THRIFT_VERSION ${THRIFT_VERSION_STRING})
  
  # Check for stdcxx.h
  if(EXISTS "${THRIFT_INCLUDE_DIR}/thrift/stdcxx.h")
    set(HAVE_THRIFT_STDCXX_H TRUE)
  endif()
  
  # Calculate THRIFT_VERSION as an integer
  if(THRIFT_VERSION)
    string(REPLACE "." ";" THRIFT_VERSION_LIST ${THRIFT_VERSION})
    list(GET THRIFT_VERSION_LIST 0 THRIFT_VERSION_MAJOR)
    list(GET THRIFT_VERSION_LIST 1 THRIFT_VERSION_MINOR)
    list(GET THRIFT_VERSION_LIST 2 THRIFT_VERSION_PATCH)
    math(EXPR THRIFT_VERSION_NUMBER "${THRIFT_VERSION_MAJOR} * 10000 + ${THRIFT_VERSION_MINOR} * 100 + ${THRIFT_VERSION_PATCH}")
  endif()
else()
  set(THRIFT_FOUND FALSE)
endif()

if(THRIFT_FOUND)
  if(NOT THRIFT_FIND_QUIETLY)
    message(STATUS "Found Thrift: ${THRIFT_LIBRARY}")
    message(STATUS "Found Thrift include: ${THRIFT_INCLUDE_DIR}")
    message(STATUS "Found Thrift compiler: ${THRIFT_COMPILER}")
    message(STATUS "Found Thrift version: ${THRIFT_VERSION}")
  endif()
else()
  if(THRIFT_FIND_REQUIRED)
    message(FATAL_ERROR "Could not find Thrift library")
  endif()
endif()
