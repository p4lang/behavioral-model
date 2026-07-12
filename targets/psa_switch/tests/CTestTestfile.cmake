# CMake generated Testfile for 
# Source directory: /home/p4/src/behavioral-model/targets/psa_switch/tests
# Build directory: /home/p4/src/behavioral-model/targets/psa_switch/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(psa_switch/test_internet_checksum "/home/p4/src/behavioral-model/targets/psa_switch/tests/test_internet_checksum")
set_tests_properties(psa_switch/test_internet_checksum PROPERTIES  _BACKTRACE_TRIPLES "/home/p4/src/behavioral-model/targets/psa_switch/tests/CMakeLists.txt;31;add_test;/home/p4/src/behavioral-model/targets/psa_switch/tests/CMakeLists.txt;0;")
add_test(psa_switch/test_hash "/home/p4/src/behavioral-model/targets/psa_switch/tests/test_hash")
set_tests_properties(psa_switch/test_hash PROPERTIES  _BACKTRACE_TRIPLES "/home/p4/src/behavioral-model/targets/psa_switch/tests/CMakeLists.txt;31;add_test;/home/p4/src/behavioral-model/targets/psa_switch/tests/CMakeLists.txt;0;")
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Tt][Ee][Ss][Tt]_[Aa][Ll][Ll])$")
  add_test(psa_switch/test_all "/home/p4/src/behavioral-model/tests/test_all")
  set_tests_properties(psa_switch/test_all PROPERTIES  _BACKTRACE_TRIPLES "/home/p4/src/behavioral-model/targets/psa_switch/tests/CMakeLists.txt;60;add_test;/home/p4/src/behavioral-model/targets/psa_switch/tests/CMakeLists.txt;0;")
endif()
