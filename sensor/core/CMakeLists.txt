# @file sensor/core/CMakeLists.txt
# @brief Portable sensor core library (no Apple APIs).
add_library(ieso_core STATIC
  src/base64.cpp
  src/bus.cpp
  src/capture_budget.cpp
  src/clock.cpp
  src/config.cpp
  ../ontology/events.cpp   # events ontology (sensor/ontology): compiled into core, which the bus depends on
  src/flight_recorder.cpp
  src/flow_control.cpp
  src/ips_parser.cpp
  src/json.cpp
  src/json_reader.cpp
  src/mailbox.cpp
  src/otlp_json.cpp
  src/pools.cpp
  src/redactor.cpp
  src/runtime.cpp
  src/sha256.cpp
  src/spool.cpp
  src/sresult.cpp
  src/time_util.cpp
  src/trace.cpp
  src/uuid.cpp)
target_include_directories(ieso_core PUBLIC include ${CMAKE_CURRENT_SOURCE_DIR}/..)  # .. = sensor/ for "ontology/events.hpp"
target_compile_definitions(ieso_core PUBLIC FMT_EXCEPTIONS=0)
target_link_libraries(ieso_core PUBLIC fmt::fmt-header-only ieso_flags)
find_package(Threads REQUIRED)
target_link_libraries(ieso_core PUBLIC Threads::Threads)
