# libDAP - Debug Adapter Protocol Implementation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C Standard](https://img.shields.io/badge/C-C99-blue.svg)](https://en.wikipedia.org/wiki/C99)
[![Build System](https://img.shields.io/badge/Build-CMake-green.svg)](https://cmake.org/)

A robust, production-ready Debug Adapter Protocol (DAP) implementation written in C, designed for integration into CPU emulators, debuggers, and debugging tools.

This project implements a Debug Adapter Protocol (DAP) server and client - to be used for whatever, but primarily made to be included in a CPU emulator.

## 🚀 Features

- **Complete DAP Implementation**: Full server and client implementation following the Debug Adapter Protocol specification
- **Advanced Threading Architecture**: Multi-threaded DAP client with responsive UI and non-blocking operations
- **Professional Memory Examination**: Industry-standard hex dump tools with base64 decoding
- **Smart Parameter Validation**: Intelligent command validation with helpful error messages and auto-completion
- **Beautiful Table Formatting**: Professional Unicode table output for threads, variables, stack traces, and scopes
- **Callback Architecture**: Clean separation between protocol handling and debugger implementation
- **Production Ready**: Used in real-world projects like [nd100x](https://github.com/HackerCorpLabs/nd100x)
- **Cross-Platform**: Supports Linux, Windows, and other POSIX-compliant systems
- **Memory Safe**: Comprehensive error handling and memory management

### Core Features
- **Dual Architecture Support**:
  - Single-threaded debugger implementation (optimized for CPU emulation)
  - Multi-threaded DAP client with responsive UI
- **Complete Debug Command Support**:
  - Launch/Attach with parameter validation
  - Step In/Out/Over with smart threading
  - Continue/Pause with state management
  - Breakpoints with comprehensive control
  - Stack trace with beautiful formatting
  - Thread information with caching
  - Variables inspection with hierarchical display
  - Scopes examination with reference tracking
  - **Memory dump functionality** with professional hex output
  - Disassembly support
- **Smart User Experience**:
  - Parameter validation with helpful error messages
  - Cached values for seamless command chaining
  - Auto-completion and smart defaults
  - Real-time event processing
  - Professional table formatting
- **Advanced Communication**:
  - TCP-based communication
  - Thread-safe message handling
  - Non-blocking operations
  - Event-driven architecture

## 📦 Components

### DAP Mock Server (Mock of a debugger backend. Use as example to integrate into your architecture)
- `src/dap_mock_server/dap_mock_server.c`: Main server implementation
- `src/dap_mock_server/dap_mock_server.h`: Main server implementation header file
- `src/dap_mock_server/dap_mock_server_main.c`: Server entry point

### DAP Client (Advanced test implementation demonstrating the DAPLibrary integration)

The DAP Client provides both single-threaded and multi-threaded implementations to test and demonstrate the DAPLibrary integration:

#### Available Clients
- **`dap_debugger`**: Single-threaded client (original implementation)
- **`dap_debugger_threaded`**: Multi-threaded client with advanced features (recommended)

#### Core Components
- `src/dap_debugger/dap_debugger.c`: Main client implementation and command registry
- `src/dap_debugger/dap_debugger_main.c`: Single-threaded client entry point
- `src/dap_debugger/dap_debugger_main_threaded.c`: Multi-threaded client entry point
- `src/dap_debugger/dap_debugger_commands.c`: Command implementations including memory dump

#### Threading Architecture (dap_debugger_threaded)
- `src/dap_debugger/dap_debugger_threads.c`: Thread management and communication
- `src/dap_debugger/dap_client_thread.c`: DAP communication thread with smart validation
- `src/dap_debugger/dap_ui_thread.c`: User interface thread with real-time input
- `src/dap_debugger/dap_debugger_threads.h`: Threading interfaces and data structures

#### User Interface Components
- `src/dap_debugger/dap_debugger_ui.c`: User interface implementation
- `src/dap_debugger/dap_debugger_ui.h`: UI interface definitions

#### Response Formatting System
- `src/dap_debugger/dap_response_formatter.c`: Professional table formatting with Unicode
- `src/dap_debugger/dap_response_formatter.h`: Formatter interfaces and column definitions

#### Help System
- `src/dap_debugger/dap_debugger_help.c`: Comprehensive help command implementation
- `src/dap_debugger/dap_debugger_help.h`: Help system interface

## 📦 Installation

### Prerequisites

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install build-essential cmake libcjson-dev libreadline-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc cmake cjson-devel readline-devel
```

**macOS:**
```bash
brew install cmake cjson readline
```

### Dependencies

- **cJSON library**:
  ```bash
  # Ubuntu/Debian
  sudo apt update
  sudo apt install libcjson-dev

  # Fedora/RHEL
  sudo dnf install cjson-devel
  ```

- **readline library**:
  ```bash
  # Ubuntu/Debian
  sudo apt install libreadline-dev

  # Fedora/RHEL
  sudo dnf install readline-devel
  ```

## 🔧 Building the Project

### CMake (Primary Build System)

1. **Generate the build system:**
```bash
cmake -B build
-- Using system cJSON library
-- Configuring done
-- Generating done
-- Build files have been written to: /home/ronny/repos/libdap/build
```

2. **Compile the project:**
```bash
cmake --build build
```

3. **The compiled binaries will be in the `build` directory.**

#### Build Configuration Options
```bash
# Debug build with executables
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_EXECUTABLES=ON
cmake --build build

# Release build with executables
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_EXECUTABLES=ON
cmake --build build
```

#### Cleaning the Build

To clean the build and start fresh:

```bash
# Remove all build artifacts
cmake --build build --target clean

# Or to remove the entire build directory
rm -rf build
```

### Using Make (CMake Wrapper)

A Makefile is included to simplify the process if you prefer using make.

```bash
$make help

libDAP makefile - CMake wrapper
-------------------------------------------------------------------------------
Targets:
  all (default) - Same as 'debug'
  debug         - Build debug version
  release       - Build release version
  sanitize      - Build with address sanitizer
  clean         - Remove build directories
  runsrv        - Build and run mock server
  rund          - Build and run the debugger
  help          - Show this help

This Makefile is a wrapper around CMake. If you prefer, you can use CMake directly:
  cmake -B build
  cmake --build build
```

#### Make Targets
```bash
# Debug build with test tools
make debug

# Release build
make release

# Run with memory checking
make runsrv  # Start server with valgrind
make run     # Start debugger with valgrind

# Clean everything
make clean
```

## 🔧 Quick Start

### Using the Library in Your Project

```c
#include <dap_server.h>

// 1. Create server configuration
DAPServerConfig config = {
    .program_path = "/path/to/your/debuggee",
    .transport = {
        .type = DAP_TRANSPORT_TCP,
        .tcp = { .port = 4711 }
    }
};

// 2. Create and initialize server
DAPServer *server = dap_server_create(&config);

// 3. Register your debugger callbacks
dap_server_register_command_callback(server, DAP_CMD_LAUNCH, my_launch_callback);
dap_server_register_command_callback(server, DAP_CMD_STEP_IN, my_step_callback);
dap_server_register_command_callback(server, DAP_CMD_CONTINUE, my_continue_callback);

// 4. Run the server
dap_server_run(server);

// 5. Cleanup
dap_server_free(server);
```

### Testing with Included Tools

**Run the mock server:**
```bash
./build/bin/dap_mock_server --debug
```

**Connect with the advanced threaded debugger (recommended):**
```bash
./build/bin/dap_debugger_threaded
```

**Or use the single-threaded debugger:**
```bash
./build/bin/dap_debugger /path/to/program.exe --debug
```

### Memory Examination Examples

Once connected to a debug session, you can examine memory with professional hex dump output:

```bash
# Basic memory examination (16 bytes default)
dap# x 0x401000

# Examine larger memory blocks
dap# x 0x401000 256

# Use symbol names
dap# memory main 64

# Examine with offset
dap# readMemory 0x401000 32 8
```

**Example output:**
```
Memory Dump:
Address: 401000 (64 bytes)

Address  | 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f | ASCII
---------|--------------------------------------------------|----------------
00401000 | 48 89 e5 48 83 ec 20 89 7d fc c7 45 f8 00 00 00 | H..H.. .}..E....
00401010 | 00 8b 45 f8 83 c0 01 89 45 f8 83 7d f8 0a 7e ef | ..E.....E..}..~.
00401020 | 8b 45 fc 48 98 48 8d 15 00 00 00 00 48 01 d0 0f | .E.H.H......H...
00401030 | b6 00 84 c0 75 02 eb 05 e8 00 00 00 00 c9 c3 55 | ....u..........U
```

### Smart Command Features

The threaded debugger includes intelligent features:

```bash
# Commands with parameter validation
dap# variables
Error: variables command requires a variables reference (get from scopes)

# Smart caching - commands remember previous results
dap# threads          # Shows available threads, caches thread ID
dap# stackTrace       # Uses cached thread ID automatically
dap# scopes           # Uses cached frame ID from stackTrace
dap# variables        # Uses cached variables reference from scopes

# Debug mode for troubleshooting
dap# debugmode        # Toggle debug output

# Server capabilities inspection (works without connection)
dap# srv              # Show DAP server capabilities and protocol compliance
dap# capabilities     # Full command name for server info
dap# server           # Alternative alias
```

### Complete Command Reference

**Execution Control:**
- `continue` (`c`, `cont`) - Resume execution
- `next` (`n`, `over`) - Step over next line
- `stepIn` (`s`, `step`) - Step into function call
- `stepOut` (`o`, `step-out`) - Step out of current function
- `pause` (`p`) - Pause execution

**Program Control:**
- `launch` (`r`, `run`) - Launch debug session
- `attach` - Attach to running process
- `restart` - Restart debug session
- `disconnect` - Disconnect from debugger
- `terminate` - Terminate debuggee

**Breakpoints:**
- `setBreakpoints` (`b`, `break`) - Set line breakpoints
- `setExceptionBreakpoints` (`ex`, `exception`) - Set exception breakpoints

**Information & Inspection:**
- `threads` (`t`) - List all threads
- `stackTrace` (`bt`, `backtrace`) - Show call stack
- `scopes` (`s`) - Show variable scopes for current frame
- `variables` (`v`, `vars`) - Show variables with hierarchy
- `evaluate` (`e`, `eval`) - Evaluate expressions
- `source` (`l`, `list`) - Get source code content

**Memory & Assembly:**
- `readMemory` (`x`, `memory`) - Professional hex dump of memory
- `disassemble` (`da`) - Disassemble code at memory location

**System & Utility:**
- `capabilities` (`srv`, `server`) - Show DAP server capabilities (works without connection)
- `debugmode` (`dm`) - Toggle debug mode for troubleshooting
- `help` (`?`, `h`) - Show command help
- `exit` (`q`, `quit`) - Exit the debugger

## 🏗️ Architecture

libDAP uses a clean callback-based architecture that separates DAP protocol handling from debugger implementation:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   DAP Client    │───▶│   libDAP Core   │───▶│ Your Debugger   │
│ (VS Code, etc.) │    │ (Protocol Layer)│    │ Implementation  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

- **libDAP Core**: Handles all DAP protocol details, message parsing, and transport
- **Your Implementation**: Provides callbacks for actual debugging operations
- **Clean Interface**: No need to understand DAP internals

## 📊 Current Status

- ✅ **Production Ready**: Core functionality is stable and battle-tested
- ✅ **Advanced Threading**: Multi-threaded DAP client with responsive UI
- ✅ **Professional Memory Tools**: Industry-standard hex dump with base64 decoding
- ✅ **Smart User Experience**: Parameter validation, caching, and auto-completion
- ✅ **Beautiful Output**: Unicode table formatting for all debug data
- ✅ **Complete Command Set**: Full DAP protocol support with validation
- ✅ **Dual Architecture**: Both single and multi-threaded implementations
- ✅ **Memory Management**: Comprehensive error handling and safety
- ✅ **Build System**: Robust CMake-based build with multiple targets
- ✅ **Debug Infrastructure**: Advanced logging and troubleshooting tools

## ⚠️ Known Issues

- Some compiler warnings about variadic macros (non-critical)
- Linter warnings about struct sigaction (non-critical)

## 🛣️ Future Improvements

- ✅ ~~Add memory inspection capabilities~~ **Completed**: Professional hex dump tools implemented
- ✅ ~~Improve error handling and recovery~~ **Completed**: Smart validation and caching implemented
- ✅ ~~Add support for more debug commands~~ **Completed**: Full DAP command set with validation
- Implement breakpoint conditions and advanced breakpoint features
- Add comprehensive unit test suite
- Expand multi-platform support and testing
- Add performance profiling and optimization tools
- Implement advanced debugging features (data breakpoints, tracepoints)
- Add plugin architecture for custom formatters
- Integrate with popular IDEs and editors

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**: Follow the existing code style
4. **Add tests**: Ensure your changes are tested
5. **Commit**: `git commit -m 'Add amazing feature'`
6. **Push**: `git push origin feature/amazing-feature`
7. **Submit a Pull Request**

### Code Style
- Use C99 standard
- Follow existing naming conventions (snake_case)
- Add documentation for public APIs
- Include error handling
- Use meaningful commit messages

### Testing
- Test on multiple platforms when possible
- Include unit tests for new functionality
- Verify with valgrind for memory issues
- Test integration with mock server

## 📋 Real-World Usage

libDAP is actively used in:
- **[nd100x](https://github.com/HackerCorpLabs/nd100x)**: A CPU emulator project using the server component

*Using libDAP in your project? Let us know by opening an issue!*

## 📊 Project Status

- ✅ **Stable**: Core functionality is production-ready
- ✅ **Maintained**: Actively developed and maintained
- ⚠️ **API Changes**: Minor breaking changes may occur (see [CHANGELOG.md](CHANGELOG.md))
- 🔄 **Semantic Versioning**: Following [SemVer](https://semver.org/) starting from v1.0.0

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/libdap/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/libdap/discussions)
- **Documentation**: Check the [docs/](docs/) directory

## 🙏 Acknowledgments

- Debug Adapter Protocol specification by Microsoft
- Contributors and users providing feedback
- The open-source community

---

**Note**: This library implements the Debug Adapter Protocol as specified by Microsoft. For protocol details, see the [official DAP specification](https://microsoft.github.io/debug-adapter-protocol/).