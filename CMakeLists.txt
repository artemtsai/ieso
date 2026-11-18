# @file CMakeLists.txt
# @brief Top-level build for the ieso endpoint sensor.
cmake_minimum_required(VERSION 3.24)

if(APPLE AND NOT CMAKE_OSX_DEPLOYMENT_TARGET)
  # std::pmr availability in libc++ on macOS.
  set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0" CACHE STRING "Minimum macOS version")
endif()

project(ieso VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(IESO_BUILD_TESTS "Build unit tests" ON)
set(IESO_SANITIZE "" CACHE STRING "Sanitizer: '', 'address' (ASan+UBSan) or 'thread' (TSan)")

# Project-wide flags (docs/STYLEGUIDE.md: no exceptions, warnings are errors).
add_library(ieso_flags INTERFACE)
target_compile_options(ieso_flags INTERFACE
  -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wno-sign-conversion
  -fno-exceptions)

if(IESO_SANITIZE STREQUAL "address")
  target_compile_options(ieso_flags INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(ieso_flags INTERFACE -fsanitize=address,undefined)
elseif(IESO_SANITIZE STREQUAL "thread")
  target_compile_options(ieso_flags INTERFACE -fsanitize=thread -fno-omit-frame-pointer)
  target_link_options(ieso_flags INTERFACE -fsanitize=thread)
elseif(NOT IESO_SANITIZE STREQUAL "")
  message(FATAL_ERROR "Unknown IESO_SANITIZE value: ${IESO_SANITIZE}")
endif()

include(FetchContent)

# {fmt}: header-only, no exceptions (replaces C++20 std::format).
FetchContent_Declare(fmt
  URL https://github.com/fmtlib/fmt/archive/refs/tags/11.0.2.tar.gz
  URL_HASH SHA256=6cb1e6d37bdcb756dbbe59be438790db409cdb4868c66e888d5df9f13f7c027f
  DOWNLOAD_EXTRACT_TIMESTAMP ON
  SYSTEM)
set(FMT_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(fmt)

if(IESO_BUILD_TESTS)
  enable_testing()
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    URL_HASH SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
    DOWNLOAD_EXTRACT_TIMESTAMP ON
    SYSTEM)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
  # GoogleTest must match our no-exceptions build.
  target_compile_definitions(gtest PUBLIC GTEST_HAS_EXCEPTIONS=0)
  target_compile_options(gtest PRIVATE -fno-exceptions)
  target_compile_options(gtest_main PRIVATE -fno-exceptions)
  if(TARGET ieso_flags AND NOT IESO_SANITIZE STREQUAL "")
    target_link_libraries(gtest PRIVATE ieso_flags)
  endif()
endif()

add_subdirectory(sensor)
