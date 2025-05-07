# Add CMake support

Fixes #1254

## Description

This PR adds CMake support to the behavioral-model project, providing an alternative to the existing autotools build system. The implementation supports all the same options as the autotools build and should work on all platforms supported by CMake.

## Changes

- Added top-level CMakeLists.txt with project configuration and options
- Added CMakeLists.txt files for all major directories (src, third_party, include, tests, targets)
- Added CMake modules for finding Thrift and gRPC
- Added configuration files for CMake
- Added documentation for building with CMake
- Updated README.md with CMake build instructions
- Added GitHub Actions workflow to test the CMake build

## Testing Done

The CMake build system has been tested with the following configurations:
- Basic build
- Build with Thrift disabled
- Build with Nanomsg disabled
- Build with debugger enabled
- Running unit tests

## How to Test

To test the CMake build system:

1. Install CMake (version 3.10 or higher)
2. Create a build directory:
   ```bash
   mkdir build
   cd build
   ```
3. Configure the build:
   ```bash
   cmake ..
   ```
4. Build the project:
   ```bash
   cmake --build .
   ```
5. Run the tests:
   ```bash
   ctest
   ```

## Documentation

- Added README.cmake.md with detailed instructions for building with CMake
- Updated README.md with basic CMake build instructions

## Limitations and Future Work

- Additional platform-specific checks may be needed, especially for Windows support
- Installation paths may need to be adjusted to match the autotools build
- Some subdirectories may need additional CMakeLists.txt files
- Some build options from the autotools build may need further refinement
