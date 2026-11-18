# @file sensor/CMakeLists.txt
# @brief Sensor: portable core, macOS OS helpers, actors, agent executable, tests.
add_subdirectory(core)
if(APPLE)
  add_subdirectory(platform/macos)
endif()
add_subdirectory(actors)
add_subdirectory(host)
if(IESO_BUILD_TESTS)
  add_subdirectory(tests)
endif()
