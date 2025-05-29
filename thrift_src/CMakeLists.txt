# Find Thrift
find_package(Thrift REQUIRED)

# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${THRIFT_INCLUDE_DIRS}
)

# Get Thrift files
file(GLOB THRIFT_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.thrift")

# Generate Thrift sources
set(THRIFT_GEN_CPP_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp)
set(THRIFT_GEN_PY_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-py)

# Create directories
file(MAKE_DIRECTORY ${THRIFT_GEN_CPP_DIR})
file(MAKE_DIRECTORY ${THRIFT_GEN_PY_DIR})

# Standard files that are common to all Thrift files
set(STANDARD_FILES
  ${THRIFT_GEN_CPP_DIR}/Standard.cpp
  ${THRIFT_GEN_CPP_DIR}/Standard.h
)

# Generate Thrift sources
foreach(THRIFT_FILE ${THRIFT_FILES})
  get_filename_component(THRIFT_NAME ${THRIFT_FILE} NAME_WE)
  
  set(THRIFT_CPP_FILES
    ${THRIFT_GEN_CPP_DIR}/${THRIFT_NAME}_constants.cpp
    ${THRIFT_GEN_CPP_DIR}/${THRIFT_NAME}_constants.h
    ${THRIFT_GEN_CPP_DIR}/${THRIFT_NAME}_types.cpp
    ${THRIFT_GEN_CPP_DIR}/${THRIFT_NAME}_types.h
  )
  
  add_custom_command(
    OUTPUT ${THRIFT_CPP_FILES}
    COMMAND ${THRIFT_COMPILER} --gen cpp -r -o ${CMAKE_CURRENT_BINARY_DIR} ${THRIFT_FILE}
    COMMAND ${THRIFT_COMPILER} --gen py -r -o ${CMAKE_CURRENT_BINARY_DIR} ${THRIFT_FILE}
    DEPENDS ${THRIFT_FILE}
    COMMENT "Generating Thrift files for ${THRIFT_NAME}"
  )
  
  list(APPEND ALL_THRIFT_CPP_FILES ${THRIFT_CPP_FILES})
endforeach()

# Add Standard files once
list(APPEND ALL_THRIFT_CPP_FILES ${STANDARD_FILES})

# Create runtimestubs library
add_library(runtimestubs STATIC ${ALL_THRIFT_CPP_FILES})

target_link_libraries(runtimestubs
  ${THRIFT_LIBRARIES}
)

# Install headers
install(DIRECTORY ${THRIFT_GEN_CPP_DIR}/
  DESTINATION include
  FILES_MATCHING PATTERN "*.h"
)

# Install Python modules
install(DIRECTORY ${THRIFT_GEN_PY_DIR}/
  DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python
  FILES_MATCHING PATTERN "*.py"
)
