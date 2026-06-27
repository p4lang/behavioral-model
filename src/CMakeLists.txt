# SPDX-FileCopyrightText: 2025 Glen Gibb
#
# SPDX-License-Identifier: Apache-2.0

# Add subdirectories
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
  $<TARGET_OBJECTS:bmi>
)
target_link_libraries(bmall
  # FIXME: Is this scope correct?
  PUBLIC
    Boost::program_options
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

# Match the autoconf install surface, which provides a shared wrapper library
# for applications using the nanomsg helpers.
if(WITH_NANOMSG)
  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/bmp4apps_dummy.cpp
    "namespace bm { namespace cmake { void bmp4apps_dummy() {} } }\n"
  )

  add_library(bmp4apps SHARED
    ${CMAKE_CURRENT_BINARY_DIR}/bmp4apps_dummy.cpp
  )

  target_link_libraries(bmp4apps
    PUBLIC
      bmapps
  )

  install(TARGETS bmp4apps
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
  )
endif()
