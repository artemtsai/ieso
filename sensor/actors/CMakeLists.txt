# @file sensor/actors/CMakeLists.txt
# @brief All actors (DESIGN.md §8), one folder per actor with its .hpp/.cpp side by side.
#        Include as "<actor>/<actor>.hpp"; this directory is the public include root.
add_library(ieso_actors STATIC
  anomaly/anomaly.cpp
  cloud_client/cloud_client.cpp
  diagnostics/diagnostics.cpp
  outbox/outbox.cpp
  pii_filter/pii_filter.cpp
  spooler/spooler.cpp)
target_include_directories(ieso_actors PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
find_package(CURL REQUIRED)
target_link_libraries(ieso_actors PUBLIC ieso_core CURL::libcurl)

if(APPLE)
  add_library(ieso_actors_macos STATIC
    log_collector/log_collector.cpp
    process_watcher/process_watcher.cpp
    resource_sampler/resource_sampler.cpp
    ui_observer/ui_observer.cpp)
  target_link_libraries(ieso_actors_macos PUBLIC ieso_actors ieso_macos)
endif()
