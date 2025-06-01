# Assumption: this subdir is only included if thrift is present

# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${THRIFT_INCLUDE_DIRS}
)

# Identify Thrift files
file(GLOB THRIFT_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.thrift")

# Set up build dirs
set(THRIFT_GEN_CPP_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp)
set(THRIFT_GEN_PY_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-py)

# Export the build directories as they are use by the bm_runtime build
set(THRIFT_SRC_GEN_CPP_DIR ${THRIFT_GEN_CPP_DIR} PARENT_SCOPE)
set(THRIFT_SRC_GEN_PY_DIR ${THRIFT_GEN_PY_DIR} PARENT_SCOPE)

# Generate Thrift sources
foreach(THRIFT_FILE ${THRIFT_FILES})
  generate_thrift(${THRIFT_FILE} THRIFT_CPP_FILES
    GEN_CPP_DIR ${THRIFT_GEN_CPP_DIR}/bm
  )
  list(APPEND ALL_THRIFT_CPP_FILES ${THRIFT_CPP_FILES})
endforeach()

add_custom_target(genthrift_thrift_src DEPENDS ${ALL_THRIFT_CPP_FILES})

# Create runtimestubs library
add_library(runtimestubs STATIC ${ALL_THRIFT_CPP_FILES})

target_link_libraries(runtimestubs
  ${THRIFT_LIBRARIES}
)
add_dependencies(runtimestubs genthrift_thrift_src)

# Install headers
install(DIRECTORY ${THRIFT_GEN_CPP_DIR}/
  DESTINATION include
  FILES_MATCHING PATTERN "*.h"
)

# Install Python modules
install(DIRECTORY ${THRIFT_GEN_PY_DIR}/
  DESTINATION lib/python
  FILES_MATCHING PATTERN "*.py"
)
