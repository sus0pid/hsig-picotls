# Minimum CMake version
cmake_minimum_required(VERSION 3.12)

# Project name and language
project(StaticOQSProviderDemo C)

# Specify the source file
set(SOURCE_FILE static_oqsprovider.c)

# Add the executable
add_executable(static_oqsprovider ${SOURCE_FILE})

# Find OpenSSL and its libraries
find_package(OpenSSL REQUIRED)

# Add include directories for OpenSSL and OQS provider
include_directories(${OpenSSL_INCLUDE_DIR} /usr/local/include)

# Link libraries for OpenSSL and the static OQS provider
target_link_libraries(static_oqsprovider PRIVATE ${OpenSSL_CRYPTO_LIBRARY} oqsprovider)

# Optional: Set additional build properties
set_target_properties(static_oqsprovider PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
)

# Output a message to confirm the build mode
message(STATUS "Building static_oqsprovider in ${CMAKE_BUILD_TYPE} mode using liboqsprovider.a")
