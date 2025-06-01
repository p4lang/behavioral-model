# FIXME: Makefile.am contains references to WITH_SYSREPO. How is this set?

add_subdirectory(tests)

# Include directories
include_directories(
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../simple_switch
  ${CMAKE_CURRENT_SOURCE_DIR}/../../PI
)

if(WITH_THRIFT)
  include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}/../simple_switch/gen-cpp
  )
endif()

# Create simpleswitchgrpc library
add_library(simpleswitchgrpc STATIC
  switch_runner.cpp
  ${PROTO_GENERATED_FILES}
)

target_link_libraries(simpleswitchgrpc
  simpleswitch
  bmpi
  bm_grpc_dataplane
  ${PROTOBUF_LIBRARIES}
  ${GRPC_LIBRARIES}
)

target_include_directories(simpleswitchgrpc PRIVATE
  ${CMAKE_BINARY_DIR}/services/cpp_out
  ${CMAKE_BINARY_DIR}/services/grpc_out
)

if(WITH_THRIFT)
  target_link_libraries(simpleswitchgrpc
    bmruntime
    runtimestubs
    simpleswitch_thrift
  )
endif()

# Create simple_switch_grpc executable
add_executable(simple_switch_grpc
  main.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GRPCPP REQUIRED grpc++)

target_link_libraries(simple_switch_grpc PRIVATE
  simpleswitchgrpc
  pifeproto
  pigrpcserver
  pi
  pip4info
  ${PROTOBUF_LIBRARIES}
  ${GRPCPP_LIBRARIES}
)

# We follow this tutorial to link with grpc++_reflection:
# https://github.com/grpc/grpc/blob/master/doc/server_reflection_tutorial.md
#target_link_options(simple_switch_grpc PRIVATE
#  -Wl
#  --no-as-needed
#  -lgrpc++_reflection
#  --as-needed
#  -rdynamic
#)

# Install simple_switch_grpc executable
install(TARGETS simple_switch_grpc
  RUNTIME DESTINATION bin
)
