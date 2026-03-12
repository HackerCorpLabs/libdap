# DAPLibrary - Debug Adapter Protocol - Implementation Skeleton

This document outlines the suggested file structure and key components for implementing the DAP server for emulators. This is meant as a starting point for the implementation, and the actual structure may evolve as development progresses.

## File Structure

```
src/debugger/
├── CMakeLists.txt             # Build configuration
├── include/                   # Public header files
│   ├── dap_server.h           # Main server interface
│   ├── dap_protocol.h         # Protocol definitions
│   └── dap_emulator.h         # Emulator integration interface
├── src/                       # Implementation files
│   ├── dap_server.c           # Server implementation
│   ├── dap_protocol.c         # Protocol handling implementation
│   ├── dap_emulator.c         # Emulator integration implementation
│   ├── dap_handlers.c         # Request handlers
│   ├── dap_transport.c        # Communication transport (TCP/pipe)
│   ├── dap_json.c             # JSON parsing/serialization
│   ├── dap_utils.c            # Utility functions
│   └── dap_main.c             # Standalone entry point
└── tests/                     # Unit tests
    ├── test_protocol.c        # Protocol tests
    ├── test_json.c            # JSON handling tests
    └── test_transport.c       # Transport tests
```

## Key Data Structures

### Protocol Messages

```c
// Base message structure
typedef struct {
    int seq;                  // Sequence number
    char* type;               // Message type: "request", "response", "event"
} DAPMessage;

// Request structure
typedef struct {
    DAPMessage base;
    char* command;            // Command name
    void* arguments;          // Command-specific arguments
} DAPRequest;

// Response structure
typedef struct {
    DAPMessage base;
    int request_seq;          // Sequence number of the request
    bool success;             // Whether the request was successful
    char* command;            // Command name from the request
    char* message;            // Error message (if success is false)
    void* body;               // Response body
} DAPResponse;

// Event structure
typedef struct {
    DAPMessage base;
    char* event;              // Event name
    void* body;               // Event body
} DAPEvent;
```

### DAP Server State

```c
typedef struct {
    // Communication
    int connection_fd;        // File descriptor for the connection
    bool is_pipe;             // Whether using pipe or TCP
    
    // Protocol state
    int seq_counter;          // Sequence counter for outgoing messages
    bool initialized;         // Whether the server has been initialized
    
    // Debug state
    bool is_running;          // Whether the emulator is running
    int thread_id;            // Current thread ID (usually 1 for a single-threaded system)
    
    // Source mapping
    HashMap* source_map;      // Map from source lines to memory addresses
    
    // Breakpoints
    ArrayList* breakpoints;   // List of active breakpoints
    
    // Configuration
    bool verbose_logging;     // Whether to log detailed messages
    char* program_path;       // Path to the program being debugged
    
    // Emulator reference
    void* emulator_handle;    // Handle to the emulator instance
} DAPServer;
```

### Breakpoint Representation

```c
typedef struct {
    int id;                   // Breakpoint ID
    char* source_path;        // Source file path
    int line;                 // Source line number
    int column;               // Optional column number
    uint16_t address;         // Memory address
    bool verified;            // Whether the breakpoint is valid
    char* condition;          // Optional condition expression
    bool enabled;             // Whether the breakpoint is enabled
} Breakpoint;
```

## Key Functions

### Server Management

```c
// Initialize the DAP server
DAPServer* dap_server_create(void);

// Start the server on the specified port or pipe name
bool dap_server_start(DAPServer* server, const char* port_or_pipe, bool is_pipe);

// Run the main server loop - processing messages until shutdown
void dap_server_run(DAPServer* server);

// Clean up and destroy the server
void dap_server_destroy(DAPServer* server);
```

### Protocol Handling

```c
// Parse a JSON message into a DAPMessage structure
DAPMessage* dap_protocol_parse_message(const char* json);

// Serialize a DAPMessage to JSON
char* dap_protocol_serialize_message(const DAPMessage* message);

// Create a new response for a request
DAPResponse* dap_protocol_create_response(const DAPRequest* request, bool success);

// Create a new event
DAPEvent* dap_protocol_create_event(const char* event_name);
```

### Request Handlers

```c
// Handle an initialize request
void dap_handle_initialize(DAPServer* server, const DAPRequest* request);

// Handle a launch request
void dap_handle_launch(DAPServer* server, const DAPRequest* request);

// Handle a setBreakpoints request
void dap_handle_set_breakpoints(DAPServer* server, const DAPRequest* request);

// Handle a threads request
void dap_handle_threads(DAPServer* server, const DAPRequest* request);

// Handle a stackTrace request
void dap_handle_stack_trace(DAPServer* server, const DAPRequest* request);

// Handle a continue request
void dap_handle_continue(DAPServer* server, const DAPRequest* request);

// Handle a next request (step over)
void dap_handle_next(DAPServer* server, const DAPRequest* request);

// Handle a stepIn request
void dap_handle_step_in(DAPServer* server, const DAPRequest* request);

// Handle a disconnect request
void dap_handle_disconnect(DAPServer* server, const DAPRequest* request);
```

### Emulator Integration

```c
// Initialize the emulator integration
bool dap_emulator_init(DAPServer* server, const char* program_path);

// Set a breakpoint in the emulator
bool dap_emulator_set_breakpoint(DAPServer* server, uint16_t address);

// Remove a breakpoint from the emulator
bool dap_emulator_remove_breakpoint(DAPServer* server, uint16_t address);

// Continue execution
bool dap_emulator_continue(DAPServer* server);

// Step to the next instruction
bool dap_emulator_step(DAPServer* server);

// Get the current program counter
uint16_t dap_emulator_get_pc(DAPServer* server);

// Get the value of a register
uint16_t dap_emulator_get_register(DAPServer* server, int reg_id);

// Get memory value at an address
uint16_t dap_emulator_get_memory(DAPServer* server, uint16_t address);

// Set memory value at an address
bool dap_emulator_set_memory(DAPServer* server, uint16_t address, uint16_t value);
```

### Source Mapping

```c
// Load a source map file
bool dap_load_source_map(DAPServer* server, const char* map_file_path);

// Get the address for a source line
uint16_t dap_get_address_for_source(DAPServer* server, const char* source_path, int line);

// Get the source location for an address
bool dap_get_source_for_address(DAPServer* server, uint16_t address, 
                               char** source_path, int* line);
```

## Sample JSON Message Handling

Here's an example of how you might handle incoming JSON messages:

```c
void process_message(DAPServer* server, const char* json_message) {
    // Parse the message
    DAPMessage* message = dap_protocol_parse_message(json_message);
    if (!message) {
        fprintf(stderr, "Failed to parse message\n");
        return;
    }
    
    // Check message type
    if (strcmp(message->type, "request") == 0) {
        DAPRequest* request = (DAPRequest*)message;
        
        // Dispatch to the appropriate handler
        if (strcmp(request->command, "initialize") == 0) {
            dap_handle_initialize(server, request);
        }
        else if (strcmp(request->command, "launch") == 0) {
            dap_handle_launch(server, request);
        }
        else if (strcmp(request->command, "setBreakpoints") == 0) {
            dap_handle_set_breakpoints(server, request);
        }
        // ... handle other request types
        else {
            // Unknown command
            DAPResponse* response = dap_protocol_create_response(request, false);
            response->message = strdup("Unknown command");
            char* json = dap_protocol_serialize_message((DAPMessage*)response);
            dap_send_message(server, json);
            free(json);
            dap_protocol_free_response(response);
        }
    }
    
    // Free the parsed message
    dap_protocol_free_message(message);
}
```

## Main Server Loop

```c
void dap_server_run(DAPServer* server) {
    char buffer[4096];
    
    while (server->is_running) {
        // Read message (handling proper message framing)
        if (!dap_read_message(server, buffer, sizeof(buffer))) {
            break;  // Connection closed or error
        }
        
        // Process the message
        process_message(server, buffer);
    }
}
```

## Emulator Integration Changes

To support debugging in the nd100x emulator, you'll need to make the following changes:

1. Add a debug mode flag to the emulator
2. Implement a breakpoint system
3. Add APIs for external control (start, stop, step)
4. Expose register and memory inspection
5. Add callbacks for debug events (breakpoint hit, step completed, etc.)

### Example Emulator Interface

```c
// Initialize emulator in debug mode
bool emulator_init_debug(const char* program_path);

// Set a breakpoint at a memory address
bool emulator_set_breakpoint(uint16_t address);

// Clear a breakpoint at a memory address
bool emulator_clear_breakpoint(uint16_t address);

// Run until a breakpoint is hit or program terminates
bool emulator_run();

// Execute a single instruction
bool emulator_step();

// Get the current program counter
uint16_t emulator_get_pc();

// Get the current instruction
uint16_t emulator_get_instruction();

// Get a register value
uint16_t emulator_get_register(int reg_id);

// Set a register value
bool emulator_set_register(int reg_id, uint16_t value);

// Read memory
uint16_t emulator_read_memory(uint16_t address);

// Write memory
bool emulator_write_memory(uint16_t address, uint16_t value);

// Register a callback for breakpoint hit events
void emulator_on_breakpoint(void (*callback)(uint16_t address));

// Register a callback for program termination
void emulator_on_terminate(void (*callback)(int exit_code));
```

## Next Implementation Steps

1. Set up the basic project structure
2. Implement JSON parsing using a C JSON library
3. Create the TCP/pipe transport layer
4. Implement basic DAP message handling
5. Add a simple request dispatcher
6. Implement the initialize and launch requests
7. Create the emulator integration interface
8. Implement breakpoint handling
9. Add step and continue support
10. Implement stack trace and variable inspection

With this structure in place, you can start implementing the DAP server piece by piece, following the TODO list priorities. 