# DAPLibrary - Debug Adapter Protocol Implementation

This project implements a Debug Adapter Protocol (DAP) server and client  - to be used for whatever, but primarly made to be included in an cpu emulator.

## Components

### DAP Mock Server (Mock of a debugger backend. Use as example to integrate into your architecure)
- `src/dap_mock_server/dap_mock_server.c`: Main server implementation
- `src/dap_mock_server/dap_mock_server.h`: Main server implementation header file
- `src/dap_mock_server/dap_mock_server_main.c`: Server entry point

### DAP Client (Test program to test the protocol and the DAPLibrary integrated in a product)

The DAP Client is a test implementation that demonstrates the integration of the DAPLibrary in a product. It consists of several components:

#### Core Components
- `src/dap_debugger/dap_debugger.c`: Main client implementation
- `src/dap_debugger/dap_debugger_main.c`: Client entry point and command-line interface
- `src/dap_debugger/dap_debugger.h`: Client interface definitions

#### User Interface Components
- `src/dap_debugger/dap_debugger_ui.c`: User interface implementation
- `src/dap_debugger/dap_debugger_ui.h`: UI interface definitions

#### Help System
- `src/dap_debugger/dap_debugger_help.c`: Help command implementation
- `src/dap_debugger/dap_debugger_help.h`: Help system interface

## Features

- Single-threaded debugger implementation (optimized for CPU emulation)
- Basic debug commands support:
  - Launch/Attach
  - Step In/Out/Over
  - Continue/Pause
  - Breakpoints
  - Stack trace
  - Thread information (single thread)
- TCP-based communication
- Error handling and logging

## Current Status

- Server successfully handles basic debug commands
- Single-threaded implementation optimized for CPU emulation
- Memory management improvements implemented
- Build system working with proper directory structure
- Debug logging system in place

## Known Issues

- Some compiler warnings about variadic macros (non-critical)
- Linter warnings about struct sigaction (non-critical)

## Future Improvements

- Add support for more debug commands
- Implement breakpoint conditions
- Add memory inspection capabilities
- Improve error handling and recovery
- Add unit tests 


## Dependencies

- using cJSON.
  - Add the libraris
  
  ```bash
  sudo apt update
  sudo apt install libcjson-dev

  sudo apt install libreadline-dev
  ```
