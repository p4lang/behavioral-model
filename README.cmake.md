# Building BMv2 with CMake

This document describes how to build BMv2 using CMake instead of the traditional autotools build system.

## Prerequisites

The same dependencies are required as for the autotools build. You can install them using the `install_deps.sh` script:

```bash
./install_deps.sh
```

Additionally, you need CMake (version 3.10 or higher):

```bash
# Ubuntu/Debian
sudo apt-get install cmake

# CentOS/RHEL
sudo yum install cmake3

# macOS
brew install cmake
```

## Building

### Basic Build

```bash
# Create a build directory
mkdir build
cd build

# Configure the build
cmake ..

# Build
cmake --build .

# Install (optional)
sudo cmake --build . --target install
```

### Build Options

The following options can be specified during the configuration step:

```bash
# Disable Nanomsg support
cmake -DWITH_NANOMSG=OFF ..

# Disable Thrift support
cmake -DWITH_THRIFT=OFF ..

# Enable PI support
cmake -DWITH_PI=ON ..

# Enable pdfixed
cmake -DWITH_PDFIXED=ON ..

# Disable building targets
cmake -DWITH_TARGETS=OFF ..

# Enable stress tests
cmake -DWITH_STRESS_TESTS=ON ..

# Enable debugger
cmake -DENABLE_DEBUGGER=ON ..

# Enable code coverage
cmake -DENABLE_COVERAGE=ON ..

# Disable logging macros
cmake -DENABLE_LOGGING_MACROS=OFF ..

# Disable event logger
cmake -DENABLE_ELOGGER=OFF ..

# Enable module loading
cmake -DENABLE_MODULES=ON ..

# Disable undeterministic tests
cmake -DENABLE_UNDETERMINISTIC_TESTS=OFF ..

# Enable Werror (treat warnings as errors)
cmake -DENABLE_WERROR=ON ..

# Disable P4_16 stacks
cmake -DENABLE_WP4_16_STACKS=OFF ..
```

### Building with Ninja

For faster builds, you can use the Ninja build system:

```bash
# Configure with Ninja
cmake -GNinja ..

# Build
ninja

# Install (optional)
sudo ninja install
```

## Running Tests

```bash
# Run all tests
ctest

# Run specific tests
ctest -R test_name

# Run tests with verbose output
ctest -V
```

## Cleaning

```bash
# Clean build files
cmake --build . --target clean

# Remove all build files
rm -rf build/
```
