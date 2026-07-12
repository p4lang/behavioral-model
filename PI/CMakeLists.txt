# SPDX-FileCopyrightText: 2025 Glen Gibb
#
# SPDX-License-Identifier: Apache-2.0

set(BMPI_CORE_SRCS
  src/pi.cpp
  src/pi_imp.cpp
  src/pi_tables_imp.cpp
  src/pi_act_prof_imp.cpp
  src/pi_counter_imp.cpp
  src/pi_meter_imp.cpp
  src/pi_learn_imp.cpp
  src/pi_mc_imp.cpp
  src/common.h
  src/common.cpp
  src/action_helpers.h
  src/action_helpers.cpp
  src/direct_res_spec.h
  src/direct_res_spec.cpp
  src/group_selection.h
  src/group_selection.cpp
  src/device_state.h
  src/device_state.cpp
)

add_library(bmpi STATIC
  ${BMPI_CORE_SRCS}
)

target_include_directories(bmpi PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# FIXME: remove the redundant moves
target_compile_options(bmpi PRIVATE "-Wno-error=redundant-move")

set(BMPI_INSTALL_TARGETS bmpi)

if(WITH_TARGETS)
  add_library(bmpi_simple STATIC
    src/pi_clone_imp.cpp
  )
  target_compile_definitions(bmpi_simple PRIVATE WITH_SIMPLE_SWITCH=1)
  target_include_directories(bmpi_simple PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/targets/simple_switch
  )
  target_link_libraries(bmpi_simple PUBLIC bmpi)

  add_library(bmpi_psa STATIC
    src/pi_clone_imp.cpp
  )
  target_compile_definitions(bmpi_psa PRIVATE WITH_PSA_SWITCH=1)
  target_include_directories(bmpi_psa PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/targets/psa_switch
  )
  target_link_libraries(bmpi_psa PUBLIC bmpi)

  list(APPEND BMPI_INSTALL_TARGETS bmpi_simple bmpi_psa)
endif()

install(TARGETS ${BMPI_INSTALL_TARGETS}
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(FILES bm/PI/pi.h
  DESTINATION include/bm/PI
)
