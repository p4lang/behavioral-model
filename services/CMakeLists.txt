# Do we have grpc pytyhon support
find_program(GRPC_PYTHON_PLUGIN grpc_python_plugin)

set(PROTO_SRC ${CMAKE_CURRENT_SOURCE_DIR}/p4/bm/dataplane_interface.proto)
set(PROTOFLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}")

set(PROTOC_GEN_CPP_DIR ${CMAKE_CURRENT_BINARY_DIR}/cpp_out)
set(PROTOC_GEN_GRPC_DIR ${CMAKE_CURRENT_BINARY_DIR}/grpc_out)

set(PROTO_CPP_FILES
  ${PROTOC_GEN_CPP_DIR}/p4/bm/dataplane_interface.pb.cc
  ${PROTOC_GEN_CPP_DIR}/p4/bm/dataplane_interface.pb.h
)

set(PROTO_GRPC_FILES
  ${PROTOC_GEN_GRPC_DIR}/p4/bm/dataplane_interface.grpc.pb.cc
  ${PROTOC_GEN_GRPC_DIR}/p4/bm/dataplane_interface.grpc.pb.h
)

add_custom_command(
  OUTPUT ${PROTO_CPP_FILES} ${PROTO_GRPC_FILES}
  COMMAND mkdir -p ${PROTOC_GEN_CPP_DIR}
  COMMAND mkdir -p ${PROTOC_GEN_GRPC_DIR}
  COMMAND ${Protobuf_PROTOC_EXECUTABLE} ${PROTO_SRC} --proto_path ${CMAKE_CURRENT_SOURCE_DIR} --cpp_out ${PROTOC_GEN_CPP_DIR} ${PROTOFLAGS}
  COMMAND ${Protobuf_PROTOC_EXECUTABLE} ${PROTO_SRC} --proto_path ${CMAKE_CURRENT_SOURCE_DIR} --grpc_out ${PROTOC_GEN_GRPC_DIR} --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} ${PROTOFLAGS}
  DEPENDS ${PROTO_SRC}
  COMMENT "Generating protobuf files for services"
)

add_custom_target(gengrpc_services
  DEPENDS ${PROTO_CPP_FILES} ${PROTO_GRPC_FILES}
)

add_library(bm_grpc_dataplane STATIC
  ${PROTO_CPP_FILES}
  ${PROTO_GRPC_FILES}
)

add_dependencies(bm_grpc_dataplane gengrpc_services)

target_include_directories(bm_grpc_dataplane PRIVATE
  ${PROTOC_GEN_CPP_DIR}
  ${PROTOC_GEN_GRPC_DIR}
)

# Install headers
install(DIRECTORY ${PROTOC_GEN_CPP_DIR}/
  DESTINATION include
  FILES_MATCHING PATTERN "*.h"
)

install(DIRECTORY ${PROTOC_GEN_GRPC_DIR}/
  DESTINATION include
  FILES_MATCHING PATTERN "*.h"
)

# Install library
install(TARGETS bm_grpc_dataplane
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

# Python file handling
if(GRPC_PYTHON_PLUGIN)
  set(PROTOC_GEN_PY_DIR ${CMAKE_CURRENT_BINARY_DIR}/py_out)

  set(PROTO_PY_FILES
    py_out/p4/bm/dataplane_interface_pb2.py
  )

  add_custom_command(
    OUTPUT ${PROTO_PY_FILES}
    COMMAND mkdir -p ${PROTOC_GEN_PY_DIR}
    # Makefile.am also had --grpc_out ${PROTO_GEN_PY_DIR}, but the generated file is not installed?
    COMMAND ${Protobuf_PROTOC_EXECUTABLE} ${PROTO_SRC} --proto_path ${CMAKE_CURRENT_SOURCE_DIR} --python_out ${PROTOC_GEN_PY_DIR} --plugin=protoc-gen-grpc=${GRPC_PYTHON_PLUGIN} ${PROTOFLAGS}
    COMMAND touch ${PROTOC_GEN_PY_DIR}/p4/bm/__init__.py
    DEPENDS ${PROTO_SRC}
    COMMENT "Generating protobuf python files for services"
  )

  add_custom_target(gengrpc_py_services
    DEPENDS ${PROTO_PY_FILES}
  )

  add_dependencies(bm_grpc_dataplane gengrpc_py_services)

  install(DIRECTORY ${PROTOC_GEN_PY_DIR}/
    DESTINATION ${PY_SITE_PKG_DIR}
    FILES_MATCHING PATTERN "*.py"
  )
endif()
