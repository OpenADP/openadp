cmake_minimum_required(VERSION 3.16)
project(openadp-cpp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Coverage option
option(ENABLE_COVERAGE "Enable code coverage" OFF)

# Coverage flags
if(ENABLE_COVERAGE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} --coverage")
endif()

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)

# Find libcurl
find_package(CURL REQUIRED)

# Find nlohmann_json
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    # Fallback to pkg-config
    pkg_check_modules(nlohmann_json REQUIRED nlohmann_json)
endif()

# Try to find Google Test
find_package(GTest QUIET)
if(NOT GTest_FOUND)
    # Try pkg-config
    pkg_check_modules(GTEST gtest)
    if(GTEST_FOUND)
        set(GTEST_LIBRARIES ${GTEST_LIBRARIES} pthread)
    else()
        message(WARNING "Google Test not found. Tests will not be built. Install libgtest-dev to enable tests.")
        set(BUILD_TESTS OFF)
    endif()
else()
    set(BUILD_TESTS ON)
endif()

# Add include directories
include_directories(include)
include_directories(${OPENSSL_INCLUDE_DIR})

# Source files
set(OPENADP_SOURCES
    src/crypto.cpp
    src/client.cpp
    src/keygen.cpp
    src/ocrypt.cpp
    src/noise.cpp
    src/base64.cpp
    src/hex.cpp
    src/debug.cpp
    src/openadp.cpp
)

# Create the library
add_library(openadp STATIC ${OPENADP_SOURCES})

# Link libraries
target_link_libraries(openadp 
    ${OPENSSL_LIBRARIES}
    ${CURL_LIBRARIES}
)

if(nlohmann_json_FOUND)
    target_link_libraries(openadp nlohmann_json::nlohmann_json)
else()
    target_include_directories(openadp PRIVATE ${nlohmann_json_INCLUDE_DIRS})
    target_link_libraries(openadp ${nlohmann_json_LIBRARIES})
endif()

# Tools
add_executable(openadp-encrypt tools/openadp-encrypt.cpp)
target_link_libraries(openadp-encrypt openadp)

add_executable(openadp-decrypt tools/openadp-decrypt.cpp)
target_link_libraries(openadp-decrypt openadp)

add_executable(ocrypt-register tools/ocrypt-register.cpp)
target_link_libraries(ocrypt-register openadp)

add_executable(ocrypt-recover tools/ocrypt-recover.cpp)
target_link_libraries(ocrypt-recover openadp)

add_executable(noise_server tools/noise_server.cpp)
target_link_libraries(noise_server openadp)

# Test vector generator
add_executable(generate_test_vectors generate_test_vectors.cpp)
if(nlohmann_json_FOUND)
    target_link_libraries(generate_test_vectors openadp nlohmann_json::nlohmann_json)
else()
    target_include_directories(generate_test_vectors PRIVATE ${nlohmann_json_INCLUDE_DIRS})
    target_link_libraries(generate_test_vectors openadp ${nlohmann_json_LIBRARIES})
endif()

# Tests (only if Google Test is available)
if(BUILD_TESTS OR GTest_FOUND OR GTEST_FOUND)
    set(TEST_SOURCES
        tests/test_crypto.cpp
tests/test_crypto_vectors.cpp
tests/test_client.cpp
tests/test_keygen.cpp
tests/test_ocrypt.cpp
tests/test_noise.cpp
tests/test_noise_cross_language.cpp
tests/test_noise_debug.cpp
tests/test_base64.cpp
tests/test_hex.cpp
tests/test_openadp.cpp
tests/test_main.cpp
    )

    # Create test executable
    add_executable(openadp_tests ${TEST_SOURCES})

    # Link test libraries
    if(GTest_FOUND)
        target_link_libraries(openadp_tests openadp GTest::gtest GTest::gtest_main)
    elseif(GTEST_FOUND)
        target_include_directories(openadp_tests PRIVATE ${GTEST_INCLUDE_DIRS})
        target_link_libraries(openadp_tests openadp ${GTEST_LIBRARIES})
    endif()

    # Enable testing
    enable_testing()
    add_test(NAME openadp_unit_tests COMMAND openadp_tests)
    
    message(STATUS "Tests enabled. Run 'make openadp_tests' to build tests.")
else()
    message(STATUS "Tests disabled. Google Test not found.")
endif()

# Install targets
install(TARGETS openadp openadp-encrypt openadp-decrypt ocrypt-register ocrypt-recover
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/ DESTINATION include) 