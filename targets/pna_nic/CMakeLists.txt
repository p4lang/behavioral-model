# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

# Create pnanic library
add_library(pnanic STATIC
  pna_nic.cpp
)

target_link_libraries(pnanic
  bmsim
  bflpmtrie
  bmi
  jsoncpp
  Boost::system
  Boost::program_options
  Boost::filesystem
  ${THRIFT_LIBRARIES}
)

# Create pna_nic executable
add_executable(pna_nic
  main.cpp
)

target_link_libraries(pna_nic
  bmruntime
  runtimestubs
  pnanic
)

# Install pna_nic executable
install(TARGETS pna_nic
  RUNTIME DESTINATION bin
)
