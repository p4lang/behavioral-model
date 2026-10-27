# SPDX-FileCopyrightText: 2026 Yuao Ma
#
# SPDX-License-Identifier: Apache-2.0

set(PROTO_SRC ${CMAKE_CURRENT_SOURCE_DIR}/packet_trace.proto)
set(PROTOFLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}")
set(PROTOC_GEN_CPP_DIR ${CMAKE_CURRENT_BINARY_DIR}/cpp_out)

set(PROTO_CPP_FILES
  ${PROTOC_GEN_CPP_DIR}/packet_trace.pb.cc
  ${PROTOC_GEN_CPP_DIR}/packet_trace.pb.h
)

add_custom_command(
  OUTPUT ${PROTO_CPP_FILES}
  COMMAND mkdir -p ${PROTOC_GEN_CPP_DIR}
  COMMAND ${Protobuf_PROTOC_EXECUTABLE} ${PROTO_SRC} --cpp_out ${PROTOC_GEN_CPP_DIR} ${PROTOFLAGS}
  DEPENDS ${PROTO_SRC}
  COMMENT "Generating protobuf files for packet trace"
)

add_custom_target(genproto_packet_trace
  DEPENDS ${PROTO_CPP_FILES}
)

add_library(bm_packet_trace_proto STATIC
  ${PROTO_CPP_FILES}
)

add_dependencies(bm_packet_trace_proto genproto_packet_trace)

target_include_directories(bm_packet_trace_proto PUBLIC
  ${PROTOC_GEN_CPP_DIR}
)

target_link_libraries(bm_packet_trace_proto PUBLIC protobuf::libprotobuf)
