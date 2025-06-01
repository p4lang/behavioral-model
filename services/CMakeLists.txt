# FIXME: need to handle python part from makefile

set(PROTO_SRC ${CMAKE_CURRENT_SOURCE_DIR}/p4/bm/dataplane_interface.proto)
set(PROTOFLAGS "-I ${CMAKE_CURRENT_SOURCE_DIR}")

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

# FIXME: port python code from Makefile.am

add_custom_command(
  OUTPUT ${PROTO_CPP_FILES} ${PROTO_GRPC_FILES}
  COMMAND mkdir -p ${PROTOC_GEN_CPP_DIR}
  COMMAND mkdir -p ${PROTOC_GEN_GRPC_DIR}
  COMMAND ${Protobuf_PROTOC_EXECUTABLE} ${PROTO_SRC} --proto_path ${CMAKE_CURRENT_SOURCE_DIR} --cpp_out ${PROTOC_GEN_CPP_DIR} ${PROTOFLAGS}
  COMMAND ${Protobuf_PROTOC_EXECUTABLE} ${PROTO_SRC} --proto_path ${CMAKE_CURRENT_SOURCE_DIR} --grpc_out ${PROTOC_GEN_GRPC_DIR} --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} ${PROTOFLAGS}
  # FIXME: handle python generation as well
  DEPENDS ${PROTO_SRC}
  COMMENT "Generating protobuf files for services"
)

add_library(bm_grpc_dataplane STATIC
  ${PROTO_CPP_FILES}
  ${PROTO_GRPC_FILES}
)

target_include_directories(bm_grpc_dataplane PRIVATE
  ${PROTOC_GEN_CPP_DIR}
  ${PROTOC_GEN_GRPC_DIR}
)
