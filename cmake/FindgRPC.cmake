# Find gRPC
# This module defines
#  GRPC_INCLUDE_DIRS - where to find grpc headers
#  GRPC_LIBRARIES - the libraries needed to use gRPC
#  GRPC_CPP_PLUGIN - the gRPC C++ plugin executable
#  GRPC_FOUND - True if gRPC found

# Find the gRPC include directory
find_path(GRPC_INCLUDE_DIR
  NAMES grpc/grpc.h
  PATHS /usr/local/include /usr/include
)

# Find the gRPC library
find_library(GRPC_LIBRARY
  NAMES grpc
  PATHS /usr/local/lib /usr/lib
)

# Find the gRPC C++ library
find_library(GRPCPP_LIBRARY
  NAMES grpc++
  PATHS /usr/local/lib /usr/lib
)

# Find the gRPC C++ plugin
find_program(GRPC_CPP_PLUGIN
  NAMES grpc_cpp_plugin
  PATHS /usr/local/bin /usr/bin
)

# Find the gRPC Python plugin
find_program(GRPC_PYTHON_PLUGIN
  NAMES grpc_python_plugin
  PATHS /usr/local/bin /usr/bin
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(gRPC DEFAULT_MSG
  GRPC_LIBRARY GRPCPP_LIBRARY GRPC_INCLUDE_DIR GRPC_CPP_PLUGIN)

if(GRPC_FOUND)
  set(GRPC_LIBRARIES ${GRPCPP_LIBRARY} ${GRPC_LIBRARY})
  set(GRPC_INCLUDE_DIRS ${GRPC_INCLUDE_DIR})
  
  if(NOT TARGET gRPC::grpc)
    add_library(gRPC::grpc UNKNOWN IMPORTED)
    set_target_properties(gRPC::grpc PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${GRPC_INCLUDE_DIRS}"
      IMPORTED_LOCATION "${GRPC_LIBRARY}"
    )
  endif()
  
  if(NOT TARGET gRPC::grpc++)
    add_library(gRPC::grpc++ UNKNOWN IMPORTED)
    set_target_properties(gRPC::grpc++ PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${GRPC_INCLUDE_DIRS}"
      IMPORTED_LOCATION "${GRPCPP_LIBRARY}"
      INTERFACE_LINK_LIBRARIES gRPC::grpc
    )
  endif()
  
  if(NOT TARGET gRPC::grpc_cpp_plugin)
    add_executable(gRPC::grpc_cpp_plugin IMPORTED)
    set_target_properties(gRPC::grpc_cpp_plugin PROPERTIES
      IMPORTED_LOCATION "${GRPC_CPP_PLUGIN}"
    )
  endif()
  
  if(GRPC_PYTHON_PLUGIN AND NOT TARGET gRPC::grpc_python_plugin)
    add_executable(gRPC::grpc_python_plugin IMPORTED)
    set_target_properties(gRPC::grpc_python_plugin PROPERTIES
      IMPORTED_LOCATION "${GRPC_PYTHON_PLUGIN}"
    )
  endif()
endif()
