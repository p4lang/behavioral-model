# Add library
add_library(bmruntime STATIC
  server.cpp
  SimplePreLAG_server.cpp
  SimplePre_server.cpp
  Standard_server.cpp
)

# Set include directories
target_include_directories(bmruntime PUBLIC
  ${THRIFT_SRC_GEN_CPP_DIR}
)
