# libdap - Debug Adapter Protocol Library

A C library implementing the Debug Adapter Protocol (DAP) for debugger integration. This library provides a complete implementation of the DAP protocol for building debug adapters and clients.

## Features

### Core Protocol Support
- Full JSON-RPC message format implementation
- Request/response handling with sequence management
- Event system for debug state changes
- Error handling and reporting
- Thread-safe design

### Debugging Features
- Breakpoint management system with support for:
  - Line breakpoints
  - Function breakpoints
  - Exception breakpoints
  - Data breakpoints
  - Instruction breakpoints
- Execution control:
  - Continue
  - Step over (next)
  - Step into (stepIn)
  - Step out (stepOut)
  - Pause
- Stack and variable inspection
- Memory and register access
- Source code mapping
- Thread management

### Transport Options
- TCP/IP communication
- Named pipe support
- Custom transport layer support

## Building

The library uses Make for building. To build the library:

```bash
make
```

This will create:
- Static library: `lib/libdap.a`
- Header files in `include/`

To clean the build:
```bash
make clean
```

## API Documentation

### Core Protocol

```c
// Message types
typedef enum {
    DAP_MESSAGE_REQUEST,
    DAP_MESSAGE_RESPONSE,
    DAP_MESSAGE_EVENT
} DAPMessageType;

// Basic message structure
typedef struct {
    int sequence;
    DAPMessageType type;
    union {
        DAPRequest request;
        DAPResponse response;
        DAPEvent event;
    } content;
} DAPMessage;
```

### Server Implementation

```c
// Create and configure a DAP server
DAPServer* server = dap_server_create();
DAPServerConfig config = {
    .transport = { /* transport config */ },    
};
dap_server_configure(server, &config);

// Start the server
dap_server_start(server, "localhost", 4711);

// Run the server
dap_server_run(server);

// Clean up
dap_server_destroy(server);
```

### Client Implementation

```c
// Create a DAP client
DAPClient* client = dap_client_create("localhost", 4711);

// Connect to server
dap_client_connect(client);

// Send a request
cJSON* args = cJSON_CreateObject();
cJSON_AddStringToObject(args, "program", "./test");
char* response = NULL;
dap_client_send_request(client, "launch", args, &response);

// Clean up
free(response);
cJSON_Delete(args);
dap_client_free(client);
```

## Implementation Status

### Core Protocol
- [x] JSON-RPC message format
- [x] Request/response handling
- [x] Sequence number management
- [x] Error handling
- [x] Message structure

### Commands
- [x] initialize
- [x] launch/attach
- [x] disconnect
- [x] terminate
- [x] restart
- [x] setBreakpoints
- [x] continue
- [x] next/stepIn/stepOut
- [x] pause
- [x] stackTrace
- [x] scopes/variables
- [x] source
- [x] threads

### Events
- [x] stopped
- [x] continued
- [x] exited
- [x] terminated
- [x] initialized
- [x] thread
- [x] output

## Memory Management

The library handles all memory allocations internally. Users should:
- Always call appropriate free/destroy functions
- Not modify the contents of structures directly
- Use the provided API functions for all operations

## Thread Safety

The library is designed to be thread-safe, but users should ensure proper synchronization when:
- Accessing the same server/client from multiple threads
- Modifying debug state while operations are in progress

## Error Handling

All functions that can fail return appropriate error codes:
- Negative values indicate errors
- Positive values or zero indicate success
- NULL is returned for allocation failures

## License

MIT License - See LICENSE file for details 