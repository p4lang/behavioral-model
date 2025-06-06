# Check for pcap_set_immediate_mode
include(CheckSymbolExists)
check_symbol_exists(pcap_set_immediate_mode "pcap.h" HAVE_PCAP_SET_IMMEDIATE_MODE)

# Create bmi library
add_library(bmi OBJECT
  bmi_interface.c
  bmi_port.c
)

# Set include directories
target_include_directories(bmi PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# Add PCAP fix if needed
if(HAVE_PCAP_SET_IMMEDIATE_MODE)
  target_compile_definitions(bmi PRIVATE -DWITH_PCAP_FIX)
endif()

# Add coverage flags if enabled
if(ENABLE_COVERAGE)
  target_compile_options(bmi PRIVATE ${COVERAGE_FLAGS})
endif()

# Link libraries
target_link_libraries(bmi PUBLIC
  ${PCAP_LIBRARY}
)
