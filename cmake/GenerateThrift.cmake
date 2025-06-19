# Generate files from an IDL file via Thrift
#
# By default, the output is placed in ${$CMAKE_CURRENT_BINARY_DIR}/gen-*
# To specify specific directories, add GEN_CPP_DIR <dir> and/or GEN_PY_DIR <dir>
#
# FIXME: Add return and ad of python files
function(GENERATE_THRIFT THRIFT_FILE GEN_CPP_FILE_LIST GEN_PY_NAMESPACE GEN_PY_FILE_LIST)
  cmake_parse_arguments(PARSE_ARGV 4
    ARG "" "GEN_CPP_DIR;GEN_PY_DIR" "")

  if(DEFINED ARG_GEN_CPP_DIR)
    set(GEN_CPP_DIR ${ARG_GEN_CPP_DIR})
  else()
    set(GEN_CPP_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-cpp)
  endif()
  
  if(DEFINED ARG_GEN_PY_DIR)
    set(GEN_PY_DIR ${ARG_GEN_PY_DIR})
  else()
    set(GEN_PY_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen-py)
  endif()

  file(MAKE_DIRECTORY ${GEN_CPP_DIR} ${GEN_PY_DIR})

  get_filename_component(THRIFT_NAME ${THRIFT_FILE} NAME_WE)

  # _constants files may not be generated -- depends on thrift version
  set(THRIFT_CPP_FILES
    ${GEN_CPP_DIR}/${THRIFT_NAME}_constants.cpp
    ${GEN_CPP_DIR}/${THRIFT_NAME}_constants.h
    ${GEN_CPP_DIR}/${THRIFT_NAME}_types.cpp
    ${GEN_CPP_DIR}/${THRIFT_NAME}_types.h
  )

  # Identify extra cpp files generated from service section
  file(READ ${THRIFT_FILE} thrift_content)

  string(REGEX MATCH "service +([A-Za-z0-9_]+) *{" match "${thrift_content}")

  if (match)
    string(REGEX REPLACE "service +" "" match "${match}")
    string(REGEX REPLACE " *{" "" service "${match}")
    list(APPEND THRIFT_CPP_FILES
      ${GEN_CPP_DIR}/${service}.cpp
      ${GEN_CPP_DIR}/${service}.h
    )
  endif()

  # Identify python files
  string(REGEX MATCH "namespace py +([A-Za-z0-9_.]+)" match "${thrift_content}")

  set(namespace "")
  if (match)
    string(REGEX REPLACE "namespace py +" "" namespace "${match}")
    string(REGEX REPLACE "\\." "/" namespace "${namespace}")
    set(THRIFT_PY_FILES
      ${GEN_PY_DIR}/${namespace}/constants.py
      ${GEN_PY_DIR}/${namespace}/__init__.py
      ${GEN_PY_DIR}/${namespace}/ttypes.py
    )
    if(DEFINED service)
      list(APPEND THRIFT_PY_FILES
        ${GEN_PY_DIR}/${namespace}/${service}.py
        ${GEN_PY_DIR}/${namespace}/${service}-remote
      )
    endif()
  endif()
  
  # Run thrift 
  # FIXME: port the python handling code from Makefile.am
  add_custom_command(
    OUTPUT ${THRIFT_CPP_FILES}
    COMMAND ${THRIFT_COMPILER} -out ${GEN_CPP_DIR} --gen cpp -r ${THRIFT_FILE}
    COMMAND ${THRIFT_COMPILER} -out ${GEN_PY_DIR} --gen py -r ${THRIFT_FILE}
    # Some thrift versions don't create all outputs, so touch to create dummy files if necessary
    COMMAND touch ${THRIFT_CPP_FILES}
    DEPENDS ${THRIFT_FILE}
    COMMENT "Generating Thrift files for ${THRIFT_NAME}"
  )

  # Return cpp/py file lists
  set(${GEN_CPP_FILE_LIST} ${THRIFT_CPP_FILES} PARENT_SCOPE)
  set(${GEN_PY_NAMESPACE} ${namespace} PARENT_SCOPE)
  set(${GEN_PY_FILE_LIST} ${THRIFT_PY_FILES} PARENT_SCOPE)
endfunction()
