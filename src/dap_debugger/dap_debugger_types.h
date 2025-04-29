#ifndef DAP_DEBUGGER_TYPES_H
#define DAP_DEBUGGER_TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include "dap_client.h"

// Command handler function type
typedef int (*CommandHandler)(DAPClient* client, const char* args);

typedef enum {
    CATEGORY_PROGRAM_CONTROL = 0,
    CATEGORY_EXECUTION_CONTROL = 1,
    CATEGORY_BREAKPOINTS = 2,
    CATEGORY_STACK_AND_VARIABLES = 3,
    CATEGORY_SOURCE = 4,
    CATEGORY_THREADS = 5,
    CATEGORY_DISASSEMBLY = 8,
    CATEGORY_OTHER = 10,
    CATEGORY_COUNT = 11
} CommandCategory;

typedef struct {
    // Command identification
    const char* name;           // Primary command name
    const char* alias;          // Command alias (e.g., 'q' for 'quit')
    
    // Help information
    const char* syntax;         // Command syntax (e.g., "break <line> [file]")
    const char* description;    // Brief description
    const char* request_format; // JSON request format
    const char* response_format;// JSON response format
    const char* events;         // Related DAP events
    
    // Parameter information
    bool has_options;          // Whether the command has options
    const char* option_types;  // Option types (e.g., "line|function|address")
    const char* option_descriptions; // Option descriptions
    
    // Examples (pipe-separated list of examples with descriptions)
    const char* examples;      // Example usage (e.g., "break 42|Set breakpoint at line 42|break main|Set breakpoint at function 'main'")
    
    // Execution information
    CommandCategory category;   // Command category
    bool implemented;          // Whether the command is implemented
    CommandHandler handler;     // Function pointer to handle the command
} DebuggerCommand;

#endif // DAP_DEBUGGER_TYPES_H 