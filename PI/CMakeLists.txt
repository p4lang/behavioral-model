add_library(bmpi STATIC
  src/pi.cpp
  src/pi_imp.cpp
  src/pi_tables_imp.cpp
  src/pi_act_prof_imp.cpp
  src/pi_counter_imp.cpp
  src/pi_meter_imp.cpp
  src/pi_learn_imp.cpp
  src/pi_mc_imp.cpp
  src/pi_clone_imp.cpp
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

target_include_directories(bmpi PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# FIXME: remove the redundant moves
target_compile_options(bmpi PRIVATE "-Wno-error=redundant-move")

if(WITH_TARGETS)
  target_compile_definitions(bmpi PRIVATE WITH_SIMPLE_SWITCH)

  target_include_directories(bmpi PRIVATE
    ${CMAKE_SOURCE_DIR}/targets/simple_switch
  )
endif()

install(TARGETS bmpi
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(FILES bm/PI/pi.h
  DESTINATION include/bm/PI
)
