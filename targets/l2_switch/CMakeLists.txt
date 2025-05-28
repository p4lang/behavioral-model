# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

### Create l2switch library
##add_library(l2switch STATIC
##  l2_switch.cpp
##  learn_client.cpp
##)
##
##target_link_libraries(l2switch
##  bmsim
##  bflpmtrie
##  bmi
##  jsoncpp
##  Boost::system
##  Boost::program_options
##  Boost::filesystem
##  ${THRIFT_LIBRARIES}
##)

# Create l2_switch executable
add_executable(l2_switch
  l2_switch.cpp
  primitives.cpp
)

target_link_libraries(l2_switch
  bmruntime
  runtimestubs
  #l2switch
  bmsim
  bflpmtrie
  bmi
  jsoncpp
  Boost::system
  Boost::program_options
  Boost::filesystem
  ${THRIFT_LIBRARIES}
)

# Install l2_switch executable
install(TARGETS l2_switch
  RUNTIME DESTINATION bin
)

# Install commands.txt
install(FILES commands.txt
  DESTINATION share/l2_switch
)
