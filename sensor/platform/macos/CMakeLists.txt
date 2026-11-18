# @file sensor/platform/macos/CMakeLists.txt
# @brief macOS OS helpers (libproc, subprocess, CoreFoundation RAII, diagnostics platform).
add_library(ieso_macos STATIC
  src/ecdsa_probe_verifier.cpp
  src/macos_diagnostics_platform.cpp
  src/proc_info.cpp
  src/subprocess.cpp)
target_include_directories(ieso_macos PUBLIC include)
find_package(CURL REQUIRED)
target_link_libraries(ieso_macos PUBLIC ieso_core CURL::libcurl
  "-framework CoreFoundation" "-framework CoreServices" "-framework ApplicationServices"
  "-framework CFNetwork" "-framework Security")
