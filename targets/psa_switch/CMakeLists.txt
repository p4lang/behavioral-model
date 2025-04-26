# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

# Create psaswitch library
add_library(psaswitch STATIC
  psa_switch.cpp
)

target_link_libraries(psaswitch
  bmsim
  bflpmtrie
  bmi
  jsoncpp
  Boost::system
  Boost::program_options
  Boost::filesystem
  ${THRIFT_LIBRARIES}
)

# Create psa_switch executable
add_executable(psa_switch
  main.cpp
)

target_link_libraries(psa_switch
  bmruntime
  runtimestubs
  psaswitch
)

# Install psa_switch executable
install(TARGETS psa_switch
  RUNTIME DESTINATION bin
)
