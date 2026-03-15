cmake_minimum_required(VERSION 3.20)
project(dap_gui_debugger VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Platform-specific settings (mirror root CMakeLists.txt)
if(WIN32)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_definitions(_GNU_SOURCE)
endif()

include(FetchContent)

# --- SDL3 ---
FetchContent_Declare(
    SDL3
    GIT_REPOSITORY https://github.com/libsdl-org/SDL.git
    GIT_TAG        release-3.2.8
    GIT_SHALLOW    TRUE
)
set(SDL_SHARED OFF CACHE BOOL "" FORCE)
set(SDL_STATIC ON CACHE BOOL "" FORCE)
set(SDL_TEST_LIBRARY OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(SDL3)

# --- Dear ImGui (docking branch) ---
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        docking
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(imgui)

# Build ImGui as a static library
add_library(imgui_lib STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_demo.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_sdl3.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_sdlrenderer3.cpp
)
target_include_directories(imgui_lib PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)
target_link_libraries(imgui_lib PUBLIC SDL3::SDL3-static)

# --- cJSON (mirror root pattern) ---
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(CJSON QUIET cjson)
endif()
if(NOT CJSON_FOUND)
    # Fallback to system paths
    set(CJSON_INCLUDE_DIRS "")
    set(CJSON_LIBRARIES cjson)
endif()

# --- libdap sources (recompile as separate OBJECT target) ---
set(LIBDAP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../libdap)

file(GLOB LIBDAP_SOURCES "${LIBDAP_DIR}/src/*.c")
# Remove error.c (duplicate of dap_error.c), same as root CMakeLists.txt
list(FILTER LIBDAP_SOURCES EXCLUDE REGEX ".*error\\.c$")
list(APPEND LIBDAP_SOURCES "${LIBDAP_DIR}/src/dap_error.c")
# Exclude mock server sources
list(FILTER LIBDAP_SOURCES EXCLUDE REGEX ".*/dap_mock_server/.*")

add_library(dap_objects_gui OBJECT ${LIBDAP_SOURCES})
target_include_directories(dap_objects_gui PUBLIC ${LIBDAP_DIR}/include)
if(CJSON_INCLUDE_DIRS)
    target_include_directories(dap_objects_gui PUBLIC ${CJSON_INCLUDE_DIRS})
endif()
# dap_client.c uses #include "cJSON.h" (without cjson/ prefix)
target_include_directories(dap_objects_gui PUBLIC /usr/include/cjson)
# Suppress warnings in C library when compiled alongside C++
target_compile_options(dap_objects_gui PRIVATE -w)

# Find pthreads
if(UNIX)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
endif()

# --- GUI executable ---
set(GUI_SOURCES
    src/main.cpp
    src/app.cpp
    src/debugger_client.cpp
    src/ui/ui_main.cpp
    src/ui/panel_source.cpp
    src/ui/panel_registers.cpp
    src/ui/panel_stack.cpp
    src/ui/panel_breakpoints.cpp
    src/ui/panel_console.cpp
    src/ui/panel_terminal.cpp
    src/ui/panel_threads.cpp
    src/ui/panel_protocol.cpp
    src/ui/panel_symbols.cpp
    src/ui/panel_server_info.cpp
)

add_executable(dap_gui_debugger ${GUI_SOURCES})
target_include_directories(dap_gui_debugger PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LIBDAP_DIR}/include
)
target_link_libraries(dap_gui_debugger PRIVATE
    dap_objects_gui
    imgui_lib
    SDL3::SDL3-static
    ${CJSON_LIBRARIES}
)
if(UNIX)
    target_link_libraries(dap_gui_debugger PRIVATE Threads::Threads)
endif()
