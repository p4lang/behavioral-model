# Add test_utils subdirectory
add_subdirectory(test_utils)

# Add simple_switch subdirectory
add_subdirectory(simple_switch)

# Add psa_switch subdirectory
add_subdirectory(psa_switch)

# Add pna_nic subdirectory
add_subdirectory(pna_nic)

# Add secondary targets if enabled
if(WITH_THRIFT)
  add_subdirectory(simple_router)
  add_subdirectory(l2_switch)
endif()

if(WITH_PI)
  add_subdirectory(simple_switch_grpc)
endif()
