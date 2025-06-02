# Should only be built if compiling with nanomsg

add_subdirectory(examples)

# Add library
add_library(bmapps STATIC
  notifications.cpp
  packet_pipe.cpp
)

# Link libraries
target_link_libraries(bmapps PUBLIC
  ${CMAKE_THREAD_LIBS_INIT}
  ${NANOMSG_LIBRARY}
)

if(WITH_THRIFT)
  target_sources(bmapps PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/learn.cpp
  )

  target_include_directories(bmapps PUBLIC
    ${THRIFT_SRC_GEN_CPP_DIR}
  )

  target_link_libraries(bmapps PUBLIC
    runtimestubs
    ${THRIFT_LIBRARY}
  )
endif()
