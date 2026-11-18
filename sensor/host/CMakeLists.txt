# @file sensor/host/CMakeLists.txt
# @brief ieso-sensor host process: owns the runtime and wires every actor (run mode) plus --selftest.
add_executable(ieso-sensor main.cpp)
if(APPLE)
  target_link_libraries(ieso-sensor PRIVATE ieso_actors_macos)  # brings ieso_actors, ieso_macos, ieso_core
  target_compile_definitions(ieso-sensor PRIVATE IESO_HAVE_MACOS=1)
else()
  target_link_libraries(ieso-sensor PRIVATE ieso_actors)
endif()
