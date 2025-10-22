if(WITH_NANOMSG)
  add_subdirectory(learn_client)
endif()

# Create l2_switch executable
add_executable(l2_switch
  l2_switch.cpp
  primitives.cpp
)

target_link_libraries(l2_switch
  bmruntime
  runtimestubs
  bmsim
  bmi
  jsoncpp
  Boost::program_options
  Boost::filesystem
  ${THRIFT_LIBRARIES}
)

# FIXME: Do we want to install? Not installed in Makefile.am
### Install l2_switch executable
##install(TARGETS l2_switch
##  RUNTIME DESTINATION bin
##)
##
### Install commands.txt
##install(FILES commands.txt
##  DESTINATION share/l2_switch
##)
