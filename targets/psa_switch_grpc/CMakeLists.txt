# SPDX-FileCopyrightText: 2025 Glen Gibb
#
# SPDX-License-Identifier: Apache-2.0

# FIXME: Makefile.am contains references to WITH_SYSREPO. How is this set?

# Include directories
include_directories(
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../psa_switch
  ${CMAKE_CURRENT_SOURCE_DIR}/../../PI
)

if(WITH_THRIFT)
  include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}/../psa_switch/gen-cpp
  )
endif()

# Create psaswitchgrpc library
add_library(psaswitchgrpc STATIC
  switch_runner.cpp
  ${PROTO_GENERATED_FILES}
)

target_link_libraries(psaswitchgrpc
  psaswitch
  bmpi_psa
  bm_grpc_dataplane
  ${PROTOBUF_LIBRARIES}
  ${GRPC_LIBRARIES}
)

target_include_directories(psaswitchgrpc PRIVATE
  ${CMAKE_BINARY_DIR}/services/cpp_out
  ${CMAKE_BINARY_DIR}/services/grpc_out
)

if(WITH_THRIFT)
  target_link_libraries(psaswitchgrpc
    bmruntime
    runtimestubs
    psaswitch_thrift
  )
endif()

# Create psa_switch_grpc executable
add_executable(psa_switch_grpc
  main.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GRPCPP REQUIRED grpc++)

target_link_libraries(psa_switch_grpc PRIVATE
  psaswitchgrpc
  pifeproto
  pigrpcserver
  pi
  pip4info
  ${PROTOBUF_LIBRARIES}
  ${GRPCPP_LIBRARIES}
)

if(WITH_THRIFT)
  target_link_libraries(psa_switch_grpc PRIVATE
         thrift
         psaswitch_thrift
  )
endif()

# We follow this tutorial to link with grpc++_reflection:
# https://github.com/grpc/grpc/blob/master/doc/server_reflection_tutorial.md
#target_link_options(psa_switch_grpc PRIVATE
#  -Wl
#  --no-as-needed
#  -lgrpc++_reflection
#  --as-needed
#  -rdynamic
#)

# Install psa_switch_grpc executable
install(TARGETS psa_switch_grpc
  RUNTIME DESTINATION bin
)

# Build the tests
add_subdirectory(tests)
