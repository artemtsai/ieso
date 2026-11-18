# @file sensor/tests/CMakeLists.txt
# @brief All sensor tests (GoogleTest, no exceptions), one flat folder.
#        ieso_tests: portable core + portable actors (builds on Linux too).
#        ieso_macos_tests: macOS OS helpers + macOS actors (real libproc, kqueue, subprocesses, log stream).
include(GoogleTest)

add_executable(ieso_tests
  # core
  base64_test.cpp
  bounded_queue_test.cpp
  bus_test.cpp
  capture_budget_test.cpp
  flow_control_test.cpp
  ips_parser_test.cpp
  json_reader_test.cpp
  json_test.cpp
  otlp_json_test.cpp
  pools_test.cpp
  ring_test.cpp
  runtime_test.cpp
  sha256_test.cpp
  spool_test.cpp
  sresult_trace_test.cpp
  uuid_test.cpp
  # portable actors
  anomaly_test.cpp
  cloud_client_test.cpp
  diagnostics_test.cpp
  outbox_test.cpp
  pii_filter_test.cpp
  spooler_test.cpp)
target_link_libraries(ieso_tests PRIVATE ieso_actors GTest::gtest_main)  # ieso_actors brings ieso_core
target_compile_definitions(ieso_tests PRIVATE IESO_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
gtest_discover_tests(ieso_tests DISCOVERY_TIMEOUT 30)

if(APPLE)
  add_executable(ieso_macos_tests
    # macOS OS helpers
    proc_info_test.cpp
    subprocess_test.cpp
    # macOS actors
    log_collector_test.cpp
    probe_verifier_test.cpp
    process_watcher_test.cpp
    tls_transport_test.cpp)
  target_link_libraries(ieso_macos_tests PRIVATE ieso_actors_macos GTest::gtest_main)
  target_compile_definitions(ieso_macos_tests PRIVATE IESO_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
                             IESO_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
  gtest_discover_tests(ieso_macos_tests DISCOVERY_TIMEOUT 30)
endif()
