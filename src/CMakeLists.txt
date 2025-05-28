# Add subdirectories
add_subdirectory(bf_lpm_trie)
add_subdirectory(BMI)
add_subdirectory(bm_sim)

if(WITH_THRIFT)
  add_subdirectory(bm_runtime)
endif()

if(WITH_NANOMSG)
  add_subdirectory(bm_apps)
endif()

# Create main library
add_library(bmall SHARED
  $<TARGET_OBJECTS:bmsim>
  $<TARGET_OBJECTS:bflpmtrie>
  $<TARGET_OBJECTS:bmi>
)
target_link_libraries(bmall
  PUBLIC
    jsoncpp
    Boost::system
    Boost::program_options
    Boost::filesystem
)

if(WITH_THRIFT)
  target_link_libraries(bmall
    PUBLIC
      bmruntime
      runtimestubs
      ${THRIFT_LIBRARIES}
  )
endif()

# Install library
install(TARGETS bmall
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

# Create apps library if nanomsg is enabled
# FIXME: do we need bmp4apps?
##if(WITH_NANOMSG)
##  add_library(bmp4apps SHARED)
##  target_link_libraries(bmp4apps
##    PUBLIC
##      bmapps
##  )
##
##  # Install library
##  install(TARGETS bmp4apps
##    LIBRARY DESTINATION lib
##    ARCHIVE DESTINATION lib
##  )
##endif()
