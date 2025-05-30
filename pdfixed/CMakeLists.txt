
# Get Thrift files
file(GLOB THRIFT_FILES "${CMAKE_CURRENT_SOURCE_DIR}/thrift/*.thrift")

# FIXME: delete
set(THRIFT_SRCS
  ${CMAKE_CURRENT_SOURCE_DIR}/thrift/conn_mgr_pd_rpc.thrift
  ${CMAKE_CURRENT_SOURCE_DIR}/thrift/mc_pd_rpc.thrift
  ${CMAKE_CURRENT_SOURCE_DIR}/thrift/sswitch_pd_rpc.thrift
  ${CMAKE_CURRENT_SOURCE_DIR}/thrift/res.thrift
)

message(STATUS "In pdfixed")

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
    ${THRIFT_GEN_CPP_DIR}/${THRIFT_NAME}_constants.cpp
    ${THRIFT_GEN_CPP_DIR}/${THRIFT_NAME}_constants.h
    ${THRIFT_GEN_CPP_DIR}/${THRIFT_NAME}_types.cpp
    ${THRIFT_GEN_CPP_DIR}/${THRIFT_NAME}_types.h
  )

  file(READ ${THRIFT_FILE} thrift_content)

  string(REGEX MATCH "service +([A-Za-z0-9_]+) *{" match "${thrift_content}")

  if (match)
    message(STATUS "Full match: ${match}")
    string(REGEX REPLACE "service +" "" match "${match}")
    string(REGEX REPLACE " *{" "" service "${match}")
    message(STATUS "Extracted service: ${service}")
    set(THRIFT_CPP_FILES
      ${THRIFT_CPP_FILES}
      ${THRIFT_GEN_CPP_DIR}/${service}.cpp
      ${THRIFT_GEN_CPP_DIR}/${service}.h
    )
  else()
    message(STATUS "No match: ${THRIFT_FILE}")
  endif()


  add_custom_command(
    OUTPUT ${THRIFT_CPP_FILES}
    COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp/bm
    COMMAND ${THRIFT_COMPILER} -out ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp --gen cpp -r ${THRIFT_FILE}
    COMMAND ${THRIFT_COMPILER} --gen py -r -o ${CMAKE_CURRENT_BINARY_DIR} ${THRIFT_FILE}
    # FIXME: ported from Makefile -- some thrift versions don't create all expected outputs
    COMMAND touch ${THRIFT_CPP_FILES}
    DEPENDS ${THRIFT_FILE}
    COMMENT "Generating Thrift files for ${THRIFT_NAME}"
  )

  list(APPEND ALL_THRIFT_CPP_FILES ${THRIFT_CPP_FILES})
endforeach()

add_custom_target(genthrift_pdfixed DEPENDS ${ALL_THRIFT_CPP_FILES})

# Create libraries
add_library(bmpdfixed STATIC
  src/pd_notifications.cpp
  src/pd_helpers.cpp
  src/pd_pre.cpp
  src/pd_mirroring.cpp
  src/pd_static.cpp
  src/pd_swap.cpp
)
target_link_libraries(bmpdfixed
  runtimestubs
  simpleswitch_thrift
)
target_include_directories(bmpdfixed PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/thrift_src/gen-cpp
  ${CMAKE_BINARY_DIR}/targets/simple_switch/gen-cpp
)

add_library(bmpdfixed_thrift STATIC
  thrift-src/pdfixed_rpc_server.cpp
  thrift-src/conn_mgr_pd_rpc_server.ipp
  thrift-src/mc_pd_rpc_server.ipp
  thrift-src/sswitch_pd_rpc_server.ipp
  ${ALL_THRIFT_CPP_FILES}
)
target_include_directories(bmpdfixed_thrift PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp
)
add_dependencies(bmpdfixed_thrift genthrift_pdfixed)
