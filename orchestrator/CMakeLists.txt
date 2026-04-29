cmake_minimum_required(VERSION 3.20)
project(honeypot-orchestrator VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─── vcpkg toolchain ──────────────────────────────────────────────────────────
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "vcpkg toolchain file")
endif()

# ─── Dependencies ─────────────────────────────────────────────────────────────
find_package(oatpp          REQUIRED)
find_package(oatpp-swagger  REQUIRED)
find_package(OpenSSL        REQUIRED)
find_package(nlohmann_json  REQUIRED)
find_package(PostgreSQL     REQUIRED)

# maxminddb (system package: libmaxminddb-dev)
find_library(MAXMINDDB_LIBRARY NAMES maxminddb REQUIRED)
find_path(MAXMINDDB_INCLUDE_DIR maxminddb.h REQUIRED)

# jwt-cpp (header-only; from vcpkg)
find_path(JWT_CPP_INCLUDE_DIR jwt-cpp/jwt.h REQUIRED)

# Copy Swagger resources if available
add_definitions(
    -DOATPP_SWAGGER_RES_PATH="${oatpp-swagger_INCLUDE_DIRS}/../bin/oatpp-swagger/res"
)

# ─── Orchestrator executable ──────────────────────────────────────────────────
add_executable(orchestrator
    src/App.cpp
    src/ErrorHandler.cpp
    src/auth/JwtService.cpp
    src/auth/NodeAuthInterceptor.cpp
    src/db/DbClient.cpp
    src/worker/ClassificationWorker.cpp
)

target_include_directories(orchestrator PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIR}
    ${JWT_CPP_INCLUDE_DIR}
    ${MAXMINDDB_INCLUDE_DIR}
    ${PostgreSQL_INCLUDE_DIRS}
)
target_link_libraries(orchestrator PRIVATE
    oatpp::oatpp
    oatpp::oatpp-swagger
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    ${PostgreSQL_LIBRARIES}
    ${MAXMINDDB_LIBRARY}
)

# Copy config and migration files to build directory
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config  DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/sql     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

# ─── Tests ────────────────────────────────────────────────────────────────────
option(BUILD_TESTS "Build test suite" OFF)

if(BUILD_TESTS)
    enable_testing()

    add_executable(orchestrator-test
        test/OrchestratorTest.cpp
        src/ErrorHandler.cpp
    )

    target_include_directories(orchestrator-test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${JWT_CPP_INCLUDE_DIR}
        ${MAXMINDDB_INCLUDE_DIR}
        ${PostgreSQL_INCLUDE_DIRS}
    )

    target_link_libraries(orchestrator-test PRIVATE
        oatpp::oatpp
        oatpp::oatpp-test
        nlohmann_json::nlohmann_json
        OpenSSL::SSL
        OpenSSL::Crypto
    )

    add_test(NAME orchestrator-test COMMAND orchestrator-test)
endif()

# ─── Summary ──────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "Honeypot Orchestrator Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "  PostgreSQL: ${PostgreSQL_VERSION_STRING}")
message(STATUS "")
