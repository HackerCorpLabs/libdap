# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Debug Adapter Protocol (DAP) implementation in C, designed for CPU emulators and debuggers. The core is `libdap` (a protocol library), with two test applications (mock server and interactive debugger client), plus a Python MCP server for AI-assisted debugging.

## Build Commands

```bash
# Quick build (debug, includes executables)
make debug

# Or directly with CMake
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_EXECUTABLES=ON
cmake --build build

# Release build
make release

# Clean
make clean

# Run mock server with valgrind
make runsrv

# Run debugger client with valgrind
make run
```

Build outputs go to `build/bin/` (executables) and `build/lib/` (library).

### Dependencies

```bash
sudo apt install libcjson-dev libreadline-dev cmake valgrind
```

### MCP DAP Server (Python)

```bash
cd mcp-dap-server
pip install -e .
# Run: mcp-dap-server
```

Requires Python >= 3.10 and the `mcp` package.

## Running / Testing

There is no automated test suite. Testing is manual using the two executables:

```bash
# Terminal 1: start mock server (port 4711)
./build/bin/dap_mock_server --debug

# Terminal 2: connect debugger client
./build/bin/dap_debugger ../tests/test_program.exe --debug
```

There is also a threaded debugger variant: `./build/bin/dap_debugger_threaded`

## Architecture

### Directory Layout

- `libdap/` - Core library (protocol handling, transport, message parsing)
  - `libdap/include/` - Public headers (`dap_server.h`, `dap_server_cmds.h`, `dap_client.h`, `dap_transport.h`, `dap_message.h`, `dap_types.h`, `dap_protocol.h`, `dap_error.h`)
  - `libdap/src/` - Library implementation. **Note**: `error.c` is excluded from build (duplicate of `dap_error.c`) via CMakeLists.txt filter.
- `src/dap_debugger/` - Interactive debugger client (both single-threaded and threaded variants)
- `src/dap_mock_server/` - Mock server simulating an ND-100 8-register architecture
- `mcp-dap-server/` - Python MCP server that bridges AI tools to DAP (connects to mock server or real debugger)

### Two-Layer Callback System

The core architectural pattern is a **dual-layer callback system** in the server:

1. **Protocol handlers** (`command_handlers[]` in `dap_server_cmds.c`) - Parse JSON into typed context structs, validate, call implementation callback, cleanup. ~3000 lines covering 40+ DAP commands.

2. **Implementation callbacks** (`command_callbacks[]`) - Registered by the integrator. Perform actual debugging operations. Access parsed parameters via `server->current_command.context.<command>`.

```c
// Integrator registers callbacks
dap_server_register_command_callback(server, DAP_CMD_LAUNCH, my_launch_callback);

// Inside callback, access parsed context:
LaunchCommandContext *ctx = &server->current_command.context.launch;
```

### Command Context Union

Commands flow through a union-based context in `DAPServer.current_command`:
- Protocol handler parses JSON -> stores in `server->current_command.context.<type>`
- Callback reads from same location
- `cleanup_command_context()` frees allocated memory
- **Memory ownership**: Response bodies are freed by the sending function, not by callbacks

### Lifecycle Callbacks

Three special callbacks control CPU emulator integration:
- `DAP_WAIT_FOR_DEBUGGER` - Called before command execution (acquire CPU access)
- `DAP_RELEASE_DEBUGGER` - Called after command execution (release CPU access)
- `DAP_CHECK_CPU_EVENTS` - Called every main loop iteration to poll for debugger events

### Threading Model

- **libdap core**: Single-threaded. All protocol handling runs in the main thread. Safe for single-event-loop emulators.
- **Single-threaded debugger** (`dap_debugger_main.c`): Uses `select()` to multiplex stdin + socket.
- **Multi-threaded debugger** (`dap_debugger_main_threaded.c`): Uses pthreads with a command queue (mutex + condvar). Separate client thread (DAP I/O) and UI thread (user input).

### Key Configuration

- Default port: 4711
- C99 standard, compiled with `-Wall -Wextra -pedantic`
- Platform flags: `_GNU_SOURCE` (Linux), `_CRT_SECURE_NO_WARNINGS` (Windows)
- Mock server scope IDs: LOCALS (1000), REGISTERS (1001), MEMORY (1002)

### Embedding as a Subproject

When used as a CMake subproject, set `BUILD_DAP_TEST_TOOLS=ON` from the parent to build executables. The library is built as an OBJECT library (`dap_objects`). If the parent provides a `cjson_objects` target, it will be used instead of the system cJSON.

## Integration Reference

To integrate into a CPU emulator (see `src/dap_mock_server/dap_mock_server.c` for complete example):

1. Register command callbacks via `dap_server_register_command_callback()`
2. Register lifecycle callbacks (wait/release/check) for CPU synchronization
3. Track state via `server->debugger_state`
4. Send events via `dap_server_send_event()`
5. Set capabilities via `dap_server_set_capability()`
