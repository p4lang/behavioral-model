# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# Create simple_router executable
add_executable(simple_router
  primitives.cpp
  simple_router.cpp
)

target_link_libraries(simple_router
  bmruntime
  bmsim
  bmi
  runtimestubs
  jsoncpp
  Boost::system
  Boost::program_options
  Boost::filesystem
  ${THRIFT_LIBRARIES}
)

# Install simple_router executable
install(TARGETS simple_router
  RUNTIME DESTINATION bin
)

# Install commands.txt
install(FILES commands.txt
  DESTINATION share/simple_router
)
