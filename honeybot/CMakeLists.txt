cmake_minimum_required(VERSION 3.20)
project(honeybot VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─── vcpkg toolchain ──────────────────────────────────────────────────────────
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "vcpkg toolchain file")
endif()

# ─── Dependencies (all via vcpkg) ────────────────────────────────────────────
# cpp-httplib (vendored in third_party)
# find_package(httplib    CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL    REQUIRED)
find_package(Threads    REQUIRED)

# libssh (vcpkg provides a config package)
find_package(libssh     CONFIG REQUIRED)

# ─── Honeypot executable ─────────────────────────────────────────────────────
add_executable(honeypot
    src/main.cpp
    src/http_honeypot.cpp
    src/ssh_honeypot.cpp
    src/orchestrator_forwarder.cpp
)

target_include_directories(honeypot PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

# cpp-httplib needs CPPHTTPLIB_OPENSSL_SUPPORT to enable HTTPS (SSLClient)
target_compile_definitions(honeypot PRIVATE
    CPPHTTPLIB_OPENSSL_SUPPORT
)

target_link_libraries(honeypot PRIVATE
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
    ssh                   # libssh target name
    Threads::Threads
)

# ─── Summary ──────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "Honeybot Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "")
