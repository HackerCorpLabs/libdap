cmake_minimum_required(VERSION 3.15)
project(DAP VERSION 0.1.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Platform-specific settings
if(WIN32)
    # Windows-specific settings
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    # Linux/Unix specific settings
    add_compile_definitions(_GNU_SOURCE)
endif()

# Check for option from parent project
if(NOT DEFINED BUILD_DAP_TEST_TOOLS)
    # If not defined by parent, use our own option
    option(BUILD_EXECUTABLES "Build the dap_debugger and dap_mock_server executables" OFF)
else()
    # Use the option passed by parent project
    set(BUILD_EXECUTABLES ${BUILD_DAP_TEST_TOOLS})
endif()

# Handle cJSON dependency more carefully
if(TARGET cjson_objects)
    set(CJSON_METHOD "INTERNAL")
    message(STATUS "Using internal cJSON object library")
else()
    # Try pkg-config as an alternative
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(CJSON QUIET cjson)
        if(CJSON_FOUND)
            set(CJSON_METHOD "PKG_CONFIG")
            message(STATUS "Found cJSON via pkg-config")
        endif()
    endif()
    
    # If neither worked, fallback to system paths
    if(NOT CJSON_METHOD)
        set(CJSON_METHOD "SYSTEM")
        message(STATUS "Using system cJSON library")
    endif()
endif()

# Define the source files for the DAP object library
file(GLOB DAP_SOURCES "libdap/src/*.c")

# Remove error.c from the build (duplicate of dap_error.c)
list(FILTER DAP_SOURCES EXCLUDE REGEX ".*error\\.c$")
# Include dap_error.c specifically
list(APPEND DAP_SOURCES "libdap/src/dap_error.c")

# Create the OBJECT library
add_library(dap_objects OBJECT ${DAP_SOURCES})

# Set include directories
target_include_directories(dap_objects 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}/libdap/include
)

# Find pthread on UNIX platforms
if(UNIX)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    target_link_libraries(dap_objects PUBLIC Threads::Threads)
endif()

# Handle cJSON based on detection method
if(CJSON_METHOD STREQUAL "INTERNAL")
    target_link_libraries(dap_objects PUBLIC cjson_objects)
elseif(CJSON_METHOD STREQUAL "PKG_CONFIG")
    target_include_directories(dap_objects PUBLIC ${CJSON_INCLUDE_DIRS})
    target_link_libraries(dap_objects PUBLIC ${CJSON_LIBRARIES})
else() # SYSTEM
    # On most systems, cJSON headers are in /usr/include/cjson
    target_include_directories(dap_objects PUBLIC /usr/include/cjson)
    target_link_libraries(dap_objects PUBLIC cjson)
endif()

# Add debugging flags in Debug mode
target_compile_options(dap_objects PRIVATE 
    $<$<CONFIG:Debug>:-g -O0>
    $<$<CONFIG:Release>:-O2>
)

# Add warning flags depending on compiler
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(dap_objects PRIVATE -Wall -Wextra -pedantic)
elseif(MSVC)
    target_compile_options(dap_objects PRIVATE /W4)
endif()

# Set the output directories for all targets
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Build the DAP test tools if requested
if(BUILD_EXECUTABLES)
    message(STATUS "Building DAP test tools: dap_debugger and dap_mock_server")
    
    # DAP Debugger executable
    file(GLOB DAP_DEBUGGER_SOURCES "src/dap_debugger/*.c")
    add_executable(dap_debugger ${DAP_DEBUGGER_SOURCES})
    target_link_libraries(dap_debugger PRIVATE dap_objects)
    # Include both libdap/include for headers and src/dap_debugger for local headers
    target_include_directories(dap_debugger PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src/dap_debugger
        ${CMAKE_CURRENT_SOURCE_DIR}/libdap/include
    )
    
    # DAP Mock Server executable
    file(GLOB DAP_MOCK_SERVER_SOURCES "src/dap_mock_server/*.c")
    add_executable(dap_mock_server ${DAP_MOCK_SERVER_SOURCES})
    target_link_libraries(dap_mock_server PRIVATE dap_objects)
    # Include both libdap/include for headers and src/dap_mock_server for local headers
    target_include_directories(dap_mock_server PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src/dap_mock_server
        ${CMAKE_CURRENT_SOURCE_DIR}/libdap/include
    )
else()
    message(STATUS "Skipping DAP test tools build (use --with-dap-tools to enable)")
endif()

# Install rules
install(TARGETS dap_objects
        EXPORT dap_objects-export
        OBJECTS DESTINATION lib
        PUBLIC_HEADER DESTINATION include/libdap
)

if(BUILD_EXECUTABLES)
    install(TARGETS dap_debugger dap_mock_server
            RUNTIME DESTINATION bin
    )
endif()

# Optionally print source files for debugging
# message(STATUS "DAP sources: ${DAP_SOURCES}") 