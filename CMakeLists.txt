cmake_minimum_required(VERSION 3.10)
project(TestCheck)

# Add check target
add_custom_target(check
  COMMAND ctest --output-on-failure
  COMMENT "Running tests..."
)

# Add a simple test
add_executable(simple_test simple_test.cpp)
add_test(NAME simple_test COMMAND simple_test)
