# Check for pcap_set_immediate_mode
set(CMAKE_REQUIRED_LIBRARIES "pcap")
include(CheckSymbolExists)

set(_OLD_CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")
set(CMAKE_REQUIRED_LIBRARIES pcap)

check_symbol_exists(pcap_set_immediate_mode "pcap.h" HAVE_PCAP_SET_IMMEDIATE_MODE)

set(CMAKE_REQUIRED_LIBRARIES "${_OLD_CMAKE_REQUIRED_LIBRARIES}")

# Create bmi library
add_library(bmi OBJECT
  bmi_interface.c
  bmi_port.c
)

# Add PCAP fix if needed
if(HAVE_PCAP_SET_IMMEDIATE_MODE)
  target_compile_definitions(bmi PRIVATE -DWITH_PCAP_FIX)
endif()

# Link libraries
target_link_libraries(bmi PUBLIC
  ${PCAP_LIBRARY}
)
