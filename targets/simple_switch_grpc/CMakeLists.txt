# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../simple_switch
  ${CMAKE_CURRENT_SOURCE_DIR}/../../PI
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

# Find Protobuf and gRPC
find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)

# Generate Protobuf and gRPC files
set(PROTO_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/proto/simple_switch.proto
)

set(PROTO_GENERATED_FILES
  ${CMAKE_CURRENT_BINARY_DIR}/simple_switch.pb.cc
  ${CMAKE_CURRENT_BINARY_DIR}/simple_switch.pb.h
  ${CMAKE_CURRENT_BINARY_DIR}/simple_switch.grpc.pb.cc
  ${CMAKE_CURRENT_BINARY_DIR}/simple_switch.grpc.pb.h
)

add_custom_command(
  OUTPUT ${PROTO_GENERATED_FILES}
  COMMAND ${PROTOBUF_PROTOC_EXECUTABLE}
    --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/proto
    --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
    --grpc_out=${CMAKE_CURRENT_BINARY_DIR}
    --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN}
    ${PROTO_FILES}
  DEPENDS ${PROTO_FILES}
  COMMENT "Generating Protobuf and gRPC files"
)

# Create simple_switch_grpc library
add_library(simpleswitchgrpc STATIC
  switch_runner.cpp
  ${PROTO_GENERATED_FILES}
)

target_link_libraries(simpleswitchgrpc
  simpleswitch
  bmpi
  ${PROTOBUF_LIBRARIES}
  ${GRPC_LIBRARIES}
)

# Create simple_switch_grpc executable
add_executable(simple_switch_grpc
  main.cpp
)

target_link_libraries(simple_switch_grpc
  simpleswitchgrpc
)

# Install simple_switch_grpc executable
install(TARGETS simple_switch_grpc
  RUNTIME DESTINATION bin
)
