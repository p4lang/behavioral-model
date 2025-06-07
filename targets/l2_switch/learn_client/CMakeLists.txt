# Create l2_switch executable
add_executable(learn_client
  learn_client.cpp
)

target_include_directories(learn_client PUBLIC
  ${THRIFT_SRC_GEN_CPP_DIR}
)

target_link_libraries(learn_client
  bmapps
)
