message(STATUS "In thrift_src")
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

set(THRIFT_GEN_CPP_DIR ${THRIFT_GEN_CPP_DIR} PARENT_SCOPE)
set(THRIFT_GEN_PY_DIR ${THRIFT_GEN_PY_DIR} PARENT_SCOPE)

# Create directories
file(MAKE_DIRECTORY ${THRIFT_GEN_CPP_DIR})
file(MAKE_DIRECTORY ${THRIFT_GEN_PY_DIR})

# Generate Thrift sources
foreach(THRIFT_FILE ${THRIFT_FILES})
  get_filename_component(THRIFT_NAME ${THRIFT_FILE} NAME_WE)
  
  set(THRIFT_CPP_FILES
    ${THRIFT_GEN_CPP_DIR}/bm/${THRIFT_NAME}_constants.cpp
    ${THRIFT_GEN_CPP_DIR}/bm/${THRIFT_NAME}_constants.h
    ${THRIFT_GEN_CPP_DIR}/bm/${THRIFT_NAME}_types.cpp
    ${THRIFT_GEN_CPP_DIR}/bm/${THRIFT_NAME}_types.h
    # ${THRIFT_GEN_CPP_DIR}/bm/Standard.cpp
    # ${THRIFT_GEN_CPP_DIR}/bm/Standard.h
  )

  file(READ ${THRIFT_FILE} thrift_content)

  string(REGEX MATCH "service +([A-Za-z0-9_]+) *{" match "${thrift_content}")

  if (match)
    #message(STATUS "Full match: ${match}")
    string(REGEX REPLACE "service +" "" match "${match}")
    string(REGEX REPLACE " *{" "" service "${match}")
    message(STATUS "Extracted service: ${service}")
    set(THRIFT_CPP_FILES
      ${THRIFT_CPP_FILES}
      ${THRIFT_GEN_CPP_DIR}/bm/${service}.cpp
      ${THRIFT_GEN_CPP_DIR}/bm/${service}.h
    )
  else()
    message(STATUS "No match: ${THRIFT_FILE}")
  endif()

  
  add_custom_command(
    OUTPUT ${THRIFT_CPP_FILES}
    COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp/bm
    COMMAND ${THRIFT_COMPILER} -out ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp/bm --gen cpp -r ${THRIFT_FILE}
    COMMAND ${THRIFT_COMPILER} --gen py -r -o ${CMAKE_CURRENT_BINARY_DIR} ${THRIFT_FILE}
    DEPENDS ${THRIFT_FILE}
    COMMENT "Generating Thrift files for ${THRIFT_NAME}"
  )
  
  list(APPEND ALL_THRIFT_CPP_FILES ${THRIFT_CPP_FILES})

  #add_custom_target(genthrift_${THRIFT_NAME} DEPENDS ${THRIFT_CPP_FILES})
  #set(THRIFT_DEPENDS ${THRIFT_DEPENDS} genthrift_${THRIFT_NAME})
endforeach()

add_custom_target(genthrift_thrift_src DEPENDS ${ALL_THRIFT_CPP_FILES})

# Create runtimestubs library
add_library(runtimestubs STATIC ${ALL_THRIFT_CPP_FILES})

target_link_libraries(runtimestubs
  ${THRIFT_LIBRARIES}
)
add_dependencies(runtimestubs genthrift_thrift_src)
#add_dependencies(runtimestubs ${THRIFT_DEPENDS})

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
