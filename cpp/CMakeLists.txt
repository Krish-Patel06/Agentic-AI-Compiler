cmake_minimum_required(VERSION 3.20)
project(SecureCompilerCppEngine VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Optional LLVM dependency detection (target LLVM 17+, configurable)
set(LLVM_TARGET_VERSION "17" CACHE STRING "Target LLVM major version")
find_package(LLVM ${LLVM_TARGET_VERSION} QUIET CONFIG)

if(LLVM_FOUND)
    message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
    message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
    include_directories(${LLVM_INCLUDE_DIRS})
    add_definitions(${LLVM_DEFINITIONS})
else()
    message(STATUS "Native LLVM not found; building standalone deterministic native scanners")
endif()

# Standalone IR Scanner executable
add_executable(ir_scanner
    ir_scanner/ir_scanner.cpp
)

# Standalone Program Profiler executable
add_executable(program_profiler
    profiler/profiler.cpp
)

# Standalone Statistical Benchmark Harness executable
add_executable(benchmark_harness
    benchmark/benchmark_harness.cpp
)
