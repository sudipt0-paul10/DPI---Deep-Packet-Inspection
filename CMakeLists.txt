cmake_minimum_required(VERSION 3.16)
project(dpi_engine VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Default to a release build so the engine is not accidentally benchmarked
# or demoed at -O0.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------
add_library(dpi_warnings INTERFACE)
if(MSVC)
    target_compile_options(dpi_warnings INTERFACE /W4)
else()
    target_compile_options(dpi_warnings INTERFACE -Wall -Wextra)
endif()

# ---------------------------------------------------------------------------
# dpi_core: protocol parsing, with no threading and no policy.
#   PCAP reading, Ethernet/IPv4/TCP/UDP parsing, TLS SNI / HTTP Host / DNS
#   extraction, and the shared types (FiveTuple, AppType, ...).
# ---------------------------------------------------------------------------
add_library(dpi_core STATIC
    src/core/pcap_reader.cpp
    src/core/packet_parser.cpp
    src/core/sni_extractor.cpp
    src/core/types.cpp
)
target_include_directories(dpi_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(dpi_core PRIVATE dpi_warnings)

# ---------------------------------------------------------------------------
# dpi_pipeline: the multithreaded engine built on top of dpi_core.
#   Load balancers, fast-path workers, per-worker flow tables, rules,
#   and the orchestrator.
# ---------------------------------------------------------------------------
add_library(dpi_pipeline STATIC
    src/engine/connection_tracker.cpp
    src/engine/rule_manager.cpp
    src/engine/load_balancer.cpp
    src/engine/fast_path.cpp
    src/engine/dpi_engine.cpp
)
target_link_libraries(dpi_pipeline
    PUBLIC dpi_core Threads::Threads
    PRIVATE dpi_warnings
)

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------

# The canonical engine: multithreaded DPI over a PCAP file.
add_executable(dpi_engine src/main.cpp)
target_link_libraries(dpi_engine PRIVATE dpi_pipeline dpi_warnings)

# Single-threaded baseline. Same parsing and classification, one thread,
# useful for comparing against the multithreaded engine.
add_executable(dpi_simple tools/dpi_simple.cpp)
target_link_libraries(dpi_simple PRIVATE dpi_core dpi_warnings)

# tcpdump-style per-packet header dump. A debugging aid for the parser.
add_executable(packet_dump tools/packet_dump.cpp)
target_link_libraries(packet_dump PRIVATE dpi_core dpi_warnings)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
option(DPI_BUILD_TESTS "Build the test suite" ON)
if(DPI_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
