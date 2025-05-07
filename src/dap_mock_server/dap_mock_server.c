/*
 * Copyright (c) 2025 Ronny Hansen
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>  // Added for va_list
#include <ctype.h>   // Added for isdigit() and other character classification functions
//#include <cjson/cJSON.h> ABSOLUTELY NO cJSON ALLOWD IN THIS FILE. ALL communication is via API structs
#include "dap_server.h"
#include "dap_error.h"
#include "dap_types.h"
#include "dap_transport.h"
#include "dap_protocol.h"
#include "dap_server_cmds.h"
#include <sys/stat.h>

#include "dap_mock_server.h"

// Forward declarations
struct DAPServer;

// Forward declarations for handler functions
static int cmd_next(DAPServer *server);
static int cmd_step_in(DAPServer *server);
static int cmd_step_out(DAPServer *server);
static int cmd_continue(DAPServer *server);
static int cmd_read_memory(DAPServer *server);
static int cmd_scopes(DAPServer *server);
static int cmd_variables(DAPServer *server);
static int on_set_exception_breakpoints(DAPServer *server);
static bool on_should_break_on_exception(DAPServer *server, const char* exception_id, bool is_uncaught, void* user_data);
static int clear_breakpoints_for_source(const char* source_path);
static int cmd_set_breakpoints(DAPServer* server);
static int cmd_launch(DAPServer* server);
static int cmd_restart(DAPServer* server);
static int cmd_disconnect(DAPServer* server);
static int cmd_disassemble(DAPServer* server);
static int cmd_set_variable(DAPServer *server);
static int cmd_write_memory(DAPServer *server);
static int setup_server_callbacks(DAPServer *server);

// Forward declaration for functions from libdap that we need
int dap_server_send_output_category(DAPServer *server, DAPOutputCategory category, const char *output);
int dap_server_send_output(DAPServer *server, const char *message);

// Mock debugger state
MockDebugger mock_debugger = {
    .server = NULL,
    .pc = 0,
    .last_event = DAP_EVENT_INVALID,
    .memory_size = 0,
    .memory = NULL,
    .register_count = 0,
    .registers = NULL,
    .exception_filters = NULL,
    .exception_filter_count = 0
};

// Define scope reference constants
#define SCOPE_ID_LOCALS 1000
#define SCOPE_ID_REGISTERS 1001
#define SCOPE_ID_MEMORY 1002
#define SCOPE_ID_STATUS_FLAGS 1101  // For status register flags

// Define CPU registers for ND-100
static Register cpu_registers[] = {
    {"STS", 0x0000, "bitmask", true, SCOPE_ID_STATUS_FLAGS}, // Status register with nested flags
    {"D", 0x0000, "integer", false, 0},     // Data register
    {"P", 0x1000, "integer", false, 0},     // Program counter
    {"B", 0x0000, "integer", false, 0},     // Base register
    {"L", 0x0000, "integer", false, 0},     // Link register
    {"A", 0x0000, "integer", false, 0},     // Accumulator
    {"T", 0x0000, "integer", false, 0},     // Temporary register
    {"X", 0x0000, "integer", false, 0}      // Index register
};

#define NUM_REGISTERS (sizeof(cpu_registers) / sizeof(Register))

// Define internal registers for read
static Register internal_read_registers[] = {
    {"PANC", 0x0000, "octal", false, 0}, // Panel control
    {"STS", 0x0001, "octal", false, 0},  // Status register
    {"LMP", 0x0002, "octal", false, 0},  // Panel data display buffer register
    {"PCR", 0x0003, "octal", false, 0},  // Paging control register
    {"IIE", 0x0005, "octal", false, 0},  // Internal interrupt enable register
    {"PID", 0x0006, "octal", false, 0},  // Priority interrupt detect register
    {"PIE", 0x0007, "octal", false, 0},  // Priority interrupt enable register
    {"CCL", 0x0010, "octal", false, 0},  // Cache clear register
    {"LCIL", 0x0011, "octal", false, 0}, // Lower cache inhibit limit register
    {"UCIL", 0x0012, "octal", false, 0}, // Upper cache inhibit limit register
    {"CILP", 0x0013, "octal", false, 0}, // Cache inhibit page register
    {"ECCR", 0x0015, "octal", false, 0}, // Error correction control register
    {"CS", 0x0017, "octal", false, 0}    // Control Store
};

#define NUM_INTERNAL_READ_REGISTERS (sizeof(internal_read_registers) / sizeof(Register))

// Define internal registers for write
static Register internal_write_registers[] = {
    {"PANS", 0x0000, "octal", false, 0}, // Panel status
    {"STS", 0x0001, "octal", false, 0},  // Status register
    {"OPR", 0x0002, "octal", false, 0},  // Operator's panel switch register
    {"PSR", 0x0003, "octal", false, 0},  // Paging status register
    {"PVL", 0x0004, "octal", false, 0},  // Previous level code register
    {"IIC", 0x0005, "octal", false, 0},  // Internal interrupt code register
    {"PID", 0x0006, "octal", false, 0},  // Priority interrupt detect register
    {"PIE", 0x0007, "octal", false, 0},  // Priority enable detect register
    {"CSR", 0x0010, "octal", false, 0},  // Cache status register
    {"ACTL", 0x0011, "octal", false, 0}, // Active level register
    {"ALD", 0x0012, "octal", false, 0},  // Automatic load descriptor
    {"PES", 0x0013, "octal", false, 0},  // Parity error status register
    {"PGC", 0x0014, "octal", false, 0},  // Paging control register
    {"PEA", 0x0015, "octal", false, 0},  // Parity error address register
    {"CS", 0x0017, "octal", false, 0}    // Control store
};

#define NUM_INTERNAL_WRITE_REGISTERS (sizeof(internal_write_registers) / sizeof(Register))


// Define status flags for the status register
static StatusFlag status_flags[] = {
    {"PTM", false, "flag"},  // Page Table Flag
    {"TG", false, "flag"},   // Floating point rounding flag
    {"K", false, "flag"},    // Accumulator
    {"Z", false, "flag"},    // Error flag
    {"Q", false, "flag"},    // Dynamic overflow flag
    {"O", false, "flag"},    // Static overflow flag
    {"C", false, "flag"},    // Carry flag
    {"M", false, "flag"},    // Multi-shift link flag
    {"PIL", false, "level"}, // Program Level (4 bits) - changed to bool for compatibility
    {"N100", true, "flag"},  // ND-100 flag (always 1)
    {"SEXI", false, "flag"}, // Memory management extended mode
    {"PONI", false, "flag"}, // Memory management ON flag
    {"IONI", false, "flag"}  // Interrupt system ON flag
};

#define NUM_STATUS_FLAGS (sizeof(status_flags) / sizeof(StatusFlag))


/**
 * @brief Mock memory for the debugger
 * 
 * This is a simple memory model that provides mock data for memory read requests
 */
static uint8_t mock_memory[0x10000]; // 64KB of mock memory
static bool mock_memory_initialized = false;

/**
 * @brief Initialize mock memory with a pattern
 */
static void initialize_mock_memory() {
    if (mock_memory_initialized) {
        return;
    }
    
    // Initialize with a pattern - address as the value
    for (int i = 0; i < 0x10000; i++) {
        mock_memory[i] = i & 0xFF;
    }
    
    // Add some recognizable patterns at specific addresses
    // ASCII "HELLO WORLD" at 0x1000
    const char* hello = "HELLO WORLD";
    memcpy(&mock_memory[0x1000], hello, strlen(hello));
    
    // Fibonacci sequence at 0x2000
    int a = 1, b = 1;
    mock_memory[0x2000] = a;
    mock_memory[0x2001] = b;
    for (int i = 2; i < 16; i++) {
        int next = a + b;
        mock_memory[0x2000 + i] = next & 0xFF;
        a = b;
        b = next;
    }
    
    // Program code at 0x4000 (some dummy instruction bytes)
    static const uint8_t program[] = {
        0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x89, // mov %rsp, %rbp; sub $0x10, %rsp; mov %edi, -0x4(%rbp)
        0x7d, 0xfc, 0x48, 0x89, 0x75, 0xf0, 0x8b, 0x45, // mov %rsi, -0x10(%rbp); mov -0x4(%rbp), %eax
        0xfc, 0x83, 0xc0, 0x01, 0x89, 0xc7, 0xe8, 0x00, // add $0x1, %eax; mov %eax, %edi; call ...
        0x00, 0x00, 0x00, 0x48, 0x8b, 0x45, 0xf0, 0x48  // mov -0x10(%rbp), %rax
    };
    memcpy(&mock_memory[0x4000], program, sizeof(program));
    
    mock_memory_initialized = true;
}

/**
 * @brief Read memory command handler
 * 
 * This function handles the readMemory command from DAP by:
 * 1. Extracting the memory reference, offset, and count from the command context
 * 2. Converting the memory reference to an address
 * 3. Reading the requested data from the mock memory
 * 4. Sending informative messages about the memory being read
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_read_memory(DAPServer *server) {
    if (!server) {
        return -1;
    }
    
    // Ensure mock memory is initialized
    initialize_mock_memory();
    
    DBG_MOCK_LOG("Handling readMemory command");
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Reading memory...\n");
    
    // Extract parameters from the command context
    const char* memory_reference = server->current_command.context.read_memory.memory_reference;
    uint64_t offset = server->current_command.context.read_memory.offset;
    size_t count = server->current_command.context.read_memory.count;
    
    DBG_MOCK_LOG("Memory reference: %s, offset: %llu, count: %zu", 
              memory_reference, (unsigned long long)offset, count);
    
    // Convert memory reference to an address
    char* endptr = NULL;
    uint32_t address = (uint32_t)strtoul(memory_reference, &endptr, 0);
    if (endptr == memory_reference || *endptr != '\0') {
        DBG_MOCK_LOG("Invalid memory reference format: %s", memory_reference);
        dap_server_send_output_category(server, DAP_OUTPUT_STDERR, "Error: Invalid memory reference format\n");
        return -1;
    }
    
    // Apply offset to address
    address += (uint32_t)offset;
    
    // Ensure the address is within range
    if (address >= sizeof(mock_memory)) {
        DBG_MOCK_LOG("Address out of range: 0x%x", address);
        dap_server_send_output_category(server, DAP_OUTPUT_STDERR, "Error: Address out of range\n");
        return -1;
    }
    
    // Determine how many bytes we can actually read
    size_t available_bytes = sizeof(mock_memory) - address;
    size_t bytes_to_read = (count <= available_bytes) ? count : available_bytes;
    size_t unreadable_bytes = count - bytes_to_read;
    
    // Send informative message about the memory being read
    char info_message[256];
    snprintf(info_message, sizeof(info_message), 
             "Reading %zu bytes from address 0x%08x (reference: %s, offset: 0x%llx)\n", 
             bytes_to_read, address, memory_reference, (unsigned long long)offset);
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, info_message);
    
    if (unreadable_bytes > 0) {
        snprintf(info_message, sizeof(info_message),
                "Note: %zu bytes were unreadable (beyond memory limit)\n", unreadable_bytes);
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, info_message);
    }
    
    // Format address as a string for the human-readable output
    char address_str[32];
    snprintf(address_str, sizeof(address_str), "0x%08x", address);
    
    // Show a summary of the data for informative purposes
    if (bytes_to_read > 0) {
        // Show a brief hex dump for the first few bytes
        size_t display_bytes = bytes_to_read > 16 ? 16 : bytes_to_read;
        char hex_dump[100] = "Data preview: ";
        size_t pos = strlen(hex_dump);
        
        for (size_t i = 0; i < display_bytes && pos < sizeof(hex_dump) - 5; i++) {
            snprintf(hex_dump + pos, sizeof(hex_dump) - pos, "%02x ", mock_memory[address + i]);
            pos = strlen(hex_dump);
        }
        
        if (bytes_to_read > display_bytes) {
            strcat(hex_dump, "...");
        }
        
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, hex_dump);
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "\n");
    }
    
    // The actual response with the memory data will be handled by the main handler in dap_server_cmds.c
    
    return 0;
}

/**
 * @brief Write memory command handler
 * 
 * This function handles the writeMemory command from DAP by:
 * 1. Extracting the memory reference, offset, and data from the command context
 * 2. Converting the memory reference to an address
 * 3. Sending informative messages about the memory operation
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_write_memory(DAPServer *server) {
    if (!server) {
        return -1;
    }
    
    // Ensure mock memory is initialized
    initialize_mock_memory();
    
    DBG_MOCK_LOG("Handling writeMemory command");
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Writing memory...\n");
    
    // Extract parameters from the command context
    const char* memory_reference = server->current_command.context.write_memory.memory_reference;
    uint64_t offset = server->current_command.context.write_memory.offset;
    const char* data = server->current_command.context.write_memory.data;
    bool allow_partial = server->current_command.context.write_memory.allow_partial;
    
    DBG_MOCK_LOG("Memory reference: %s, offset: %llu, allow_partial: %d", 
              memory_reference, (unsigned long long)offset, allow_partial);
    
    // Convert memory reference to an address
    char* endptr = NULL;
    uint32_t address = (uint32_t)strtoul(memory_reference, &endptr, 0);
    if (endptr == memory_reference || *endptr != '\0') {
        DBG_MOCK_LOG("Invalid memory reference format: %s", memory_reference);
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Error: Invalid memory reference format\n");
        return -1;
    }
    
    // Apply offset to address
    address += (uint32_t)offset;
    
    // Ensure the address is within range
    if (address >= sizeof(mock_memory)) {
        DBG_MOCK_LOG("Address out of range: 0x%x", address);
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Error: Address out of range\n");
        return -1;
    }
    
    // Send informative message about the memory being written
    char info_message[256];
    snprintf(info_message, sizeof(info_message), 
             "Writing to memory at address 0x%08x (reference: %s, offset: 0x%llx)\n", 
             address, memory_reference, (unsigned long long)offset);
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, info_message);
    
    // Indicate partial write status
    if (allow_partial) {
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, 
                                     "Note: Partial writes are allowed if memory boundary is reached\n");
    }
    
    // The actual memory writing and response creation will be handled by the main handler
    
    return 0;
}

/*** CALLBACKS ***/

/**
 * @brief Common handler for step operations
 * 
 * This function handles the common logic for all step commands (next, step in, step out).
 * It reads the granularity from the command context and performs the appropriate stepping.
 * 
 * @param server The DAP server instance
 * @param step_type A string describing the step type for logging ("next", "step in", "step out")
 * @return int 0 on success, non-zero on failure
 */
static int handle_step_command(DAPServer *server, const char* step_type) {
    if (!server) {
        return -1;
    }
    
    // Access the step command context
    StepCommandContext *ctx = &server->current_command.context.step;
    
    // Log the stepping action
    char log_message[256];
    snprintf(log_message, sizeof(log_message), 
             "Handling %s command for thread %d", step_type, ctx->thread_id);
    DBG_MOCK_LOG("%s", log_message);
    dap_server_send_output(server, log_message);
    
    // Handle different granularity types
    switch (ctx->granularity) {
        case DAP_STEP_GRANULARITY_INSTRUCTION:
            snprintf(log_message, sizeof(log_message), 
                     "Stepping by instruction (%s)\n", step_type);
            dap_server_send_output(server, log_message);
            
            // Increment PC by one instruction for instruction stepping
            server->debugger_state.program_counter += 1;
            break;
            
        case DAP_STEP_GRANULARITY_LINE:
            snprintf(log_message, sizeof(log_message), 
                     "Stepping by line (%s)\n", step_type);
            dap_server_send_output(server, log_message);
            
            // For line stepping, increment PC and line
            server->debugger_state.program_counter += 4;
            server->debugger_state.source_line += 1;
            break;
            
        case DAP_STEP_GRANULARITY_STATEMENT:
        default:
            snprintf(log_message, sizeof(log_message), 
                     "Stepping by statement (%s)\n", step_type);
            dap_server_send_output(server, log_message);
            
            // For statement stepping, increment PC and line (same as line in our mock)
            server->debugger_state.program_counter += 4;
            server->debugger_state.source_line += 1;
            break;
    }
    
    // Update the debugger state to indicate we've stopped
    server->debugger_state.has_stopped = true;
    
    return 0;
}

/**
 * @brief Step Next command handler
 * 
 * Handles the 'next' command by stepping over the current line/statement
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_next(DAPServer *server) {
    return handle_step_command(server, "next");
}

/**
 * @brief Step In command handler
 * 
 * Handles the 'stepIn' command by stepping into a function call
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_step_in(DAPServer *server) {
    return handle_step_command(server, "step in");
}

/**
 * @brief Step Out command handler
 * 
 * Handles the 'stepOut' command by stepping out of the current function
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_step_out(DAPServer *server) {
    return handle_step_command(server, "step out");
}

/**
 * @brief Continue command handler
 * 
 * This function handles the continue command by:
 * 1. Advancing the program counter
 * 2. Updating the source line
 * 3. Sending a continued event
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_continue(DAPServer *server) {
    if (!server) {
        return -1;
    }
    
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Continuing execution...\n");
    
    DBG_MOCK_LOG("Handling continue command");

    // Get the thread ID from debugger state - we'll default to this
    int thread_id = server->debugger_state.current_thread_id;
    
    // The continue command doesn't have a dedicated context struct in the union,
    // so we'll use the thread ID from the debugger state, but in a real implementation
    // we would add a ContinueCommandContext for the continue command similar to StepCommandContext
    bool single_thread = false;
    
    DBG_MOCK_LOG("Continue thread_id: %d, single_thread: %s", 
               thread_id, single_thread ? "true" : "false");
    
    // Mock implementation: advance the PC and source line
    mock_debugger.pc += 5; // We advance more than a step command would
    server->debugger_state.program_counter = mock_debugger.pc;
    server->debugger_state.source_line += 5;
    
    // Set the debugger state to not stopped
    server->debugger_state.has_stopped = false;
    
    // Per DAP spec, we need to send a continued event
    cJSON *event_body = cJSON_CreateObject();
    if (event_body) {
        cJSON_AddNumberToObject(event_body, "threadId", thread_id);
        cJSON_AddBoolToObject(event_body, "allThreadsContinued", !single_thread);
        
        // Send the continued event
        dap_server_send_event(server, "continued", event_body);
        
        DBG_MOCK_LOG("Sent continued event for thread %d (allThreadsContinued: %s)", 
                   thread_id, single_thread ? "false" : "true");
    }
    
    return 0;
}

/**
 * @brief Callback for setting exception breakpoints
 * 
 * @param server The DAP server
 * @return int 0 on success, non-zero on failure
 */
static int on_set_exception_breakpoints(DAPServer *server) {
    DBG_MOCK_LOG("Handling setExceptionBreakpoints request");
    
    // Access filter data from the server's current command context
    const char** filters = server->current_command.context.exception.filters;
    size_t filter_count = server->current_command.context.exception.filter_count;
    const char** conditions = server->current_command.context.exception.conditions;
    size_t condition_count = server->current_command.context.exception.condition_count;
    
    // Clear existing exception filters
    if (mock_debugger.exception_filters) {
        for (size_t i = 0; i < mock_debugger.exception_filter_count; i++) {
            free(mock_debugger.exception_filters[i].filter_id);
            free(mock_debugger.exception_filters[i].condition);
        }
        free(mock_debugger.exception_filters);
        mock_debugger.exception_filters = NULL;
        mock_debugger.exception_filter_count = 0;
    }
    
    // If no filters specified, we're done
    if (filter_count == 0 || !filters) {
        DBG_MOCK_LOG("No exception filters specified, cleared all filters");
        return 0;
    }
    
    // Allocate memory for the filters
    mock_debugger.exception_filters = calloc(filter_count, sizeof(ExceptionBreakpointFilter));
    if (!mock_debugger.exception_filters) {
        DBG_MOCK_LOG("Error: Failed to allocate memory for exception filters");
        return -1;
    }
    mock_debugger.exception_filter_count = filter_count;
    
    // Process each filter
    for (size_t i = 0; i < filter_count; i++) {
        if (filters[i]) {
            mock_debugger.exception_filters[i].filter_id = strdup(filters[i]);
            mock_debugger.exception_filters[i].enabled = true;
            
            // Check if we have a condition for this filter
            if (conditions && i < condition_count && conditions[i]) {
                mock_debugger.exception_filters[i].condition = strdup(conditions[i]);
                DBG_MOCK_LOG("Added exception filter '%s' with condition: %s", 
                          mock_debugger.exception_filters[i].filter_id,
                          mock_debugger.exception_filters[i].condition);
            } else {
                mock_debugger.exception_filters[i].condition = NULL;
                DBG_MOCK_LOG("Added exception filter '%s' with no condition", 
                          mock_debugger.exception_filters[i].filter_id);
            }
        }
    }
    
    return 0;
}

/**
 * @brief Callback to check if an exception should cause a break
 * 
 * @param server The DAP server
 * @param exception_id The ID of the exception
 * @param is_uncaught Whether the exception is uncaught
 * @param user_data User data (MockDebugger instance)
 * @return true if the exception should break execution, false otherwise
 */
static bool on_should_break_on_exception(
    DAPServer *server,
    const char* exception_id,
    bool is_uncaught,
    void* user_data
) {
    (void)server; // Unused parameter
    (void)user_data; // user_data is mock_debugger, but we access it directly
    
    DBG_MOCK_LOG("Checking if should break on exception: %s (uncaught: %d)", 
                exception_id ? exception_id : "unknown", is_uncaught);
    
    // If no exception filters are configured, don't break
    if (!mock_debugger.exception_filters || mock_debugger.exception_filter_count == 0) {
        DBG_MOCK_LOG("No exception filters configured, not breaking");
        return false;
    }
    
    // Check each filter
    for (size_t i = 0; i < mock_debugger.exception_filter_count; i++) {
        if (!mock_debugger.exception_filters[i].enabled) {
            DBG_MOCK_LOG("Filter '%s' is disabled, skipping", 
                      mock_debugger.exception_filters[i].filter_id);
            continue;
        }
        
        // Check if filter matches
        if (strcmp(mock_debugger.exception_filters[i].filter_id, "all") == 0) {
            // "all" filter matches any exception
            DBG_MOCK_LOG("Filter 'all' matches, breaking");
            return true;
        } else if (strcmp(mock_debugger.exception_filters[i].filter_id, "uncaught") == 0) {
            // "uncaught" filter only matches uncaught exceptions
            if (is_uncaught) {
                DBG_MOCK_LOG("Filter 'uncaught' matches uncaught exception, breaking");
                return true;
            }
            DBG_MOCK_LOG("Filter 'uncaught' doesn't match caught exception");
        } else if (exception_id && strcmp(mock_debugger.exception_filters[i].filter_id, exception_id) == 0) {
            // Custom filter matches specific exception ID
            DBG_MOCK_LOG("Filter '%s' matches exception ID, breaking", 
                      mock_debugger.exception_filters[i].filter_id);
            return true;
        } else {
            DBG_MOCK_LOG("Filter '%s' doesn't match exception '%s'", 
                      mock_debugger.exception_filters[i].filter_id, 
                      exception_id ? exception_id : "unknown");
        }
    }
    
    DBG_MOCK_LOG("No matching filters, not breaking");
    return false;
}

/**
 * @brief Helper function to clear all breakpoints for a specific source file
 * 
 * @param source_path Source file path
 * @return int Number of breakpoints cleared
 */
static int clear_breakpoints_for_source(const char* source_path) {
    if (!source_path) {
        return 0;
    }
    
    int cleared_count = 0;
    
    // First, free memory for breakpoints with matching source path
    for (int i = 0; i < mock_debugger.breakpoint_count; i++) {
        if (mock_debugger.breakpoints[i].source_path && 
            strcmp(mock_debugger.breakpoints[i].source_path, source_path) == 0) {
            
            // Free all allocated strings
            free(mock_debugger.breakpoints[i].source_path);
            free(mock_debugger.breakpoints[i].source_name);
            if (mock_debugger.breakpoints[i].condition) {
                free(mock_debugger.breakpoints[i].condition);
            }
            if (mock_debugger.breakpoints[i].hit_condition) {
                free(mock_debugger.breakpoints[i].hit_condition);
            }
            if (mock_debugger.breakpoints[i].log_message) {
                free(mock_debugger.breakpoints[i].log_message);
            }
            
            // Mark as inactive by setting id to 0
            mock_debugger.breakpoints[i].id = 0;
            cleared_count++;
        }
    }
    
    // Now compact the array by removing cleared breakpoints
    if (cleared_count > 0) {
        int write_idx = 0;
        for (int read_idx = 0; read_idx < mock_debugger.breakpoint_count; read_idx++) {
            if (mock_debugger.breakpoints[read_idx].id != 0) {
                // Only copy if we're not at the same position
                if (write_idx != read_idx) {
                    mock_debugger.breakpoints[write_idx] = mock_debugger.breakpoints[read_idx];
                }
                write_idx++;
            }
        }
        mock_debugger.breakpoint_count = write_idx;
    }
    
    return cleared_count;
}

/**
 * @brief Command callback for setting breakpoints
 * 
 * @param server DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_set_breakpoints(DAPServer* server) {
    DBG_MOCK_LOG("Handling setBreakpoints request");
    
    // Extract source file info from breakpoint context
    const char* source_path = server->current_command.context.breakpoint.source_path;
    
    int breakpoint_count = server->current_command.context.breakpoint.breakpoint_count;
    
    if (!source_path || breakpoint_count <= 0) {
        DBG_MOCK_LOG("Missing required breakpoint information");
        return -1;
    }
    
    // Get filename from path
    const char* source_name = strrchr(source_path, '/');
    if (source_name) {
        source_name++; // Skip the slash
    } else {
        source_name = source_path; // No slash found, use the whole path
    }
    
    DBG_MOCK_LOG("Setting %d breakpoints in %s", breakpoint_count, source_path);
    
    // Step 1: Clear existing breakpoints for this source
    clear_breakpoints_for_source(source_path);
    
    // Step 2: Ensure we have enough capacity for new breakpoints
    if (mock_debugger.breakpoint_count + breakpoint_count > mock_debugger.breakpoint_capacity) {
        int new_capacity = mock_debugger.breakpoint_capacity == 0 ? 16 : mock_debugger.breakpoint_capacity * 2;
        while (new_capacity < mock_debugger.breakpoint_count + breakpoint_count) {
            new_capacity *= 2;
        }
        
        MockBreakpoint* new_breakpoints = realloc(mock_debugger.breakpoints, 
                                                 new_capacity * sizeof(MockBreakpoint));
        if (!new_breakpoints) {
            DBG_MOCK_LOG("Failed to allocate memory for breakpoints");
            return -1;
        }
        
        mock_debugger.breakpoints = new_breakpoints;
        mock_debugger.breakpoint_capacity = new_capacity;
    }
    
    // Step 3: Add each new breakpoint
    for (int i = 0; i < breakpoint_count; i++) {
        int bp_idx = mock_debugger.breakpoint_count;
        memset(&mock_debugger.breakpoints[bp_idx], 0, sizeof(MockBreakpoint));
        
        // Set basic properties
        mock_debugger.breakpoints[bp_idx].id = bp_idx + 1; // 1-based IDs
        mock_debugger.breakpoints[bp_idx].verified = true; // Mock always verifies
        
        // Get the line number from the breakpoints array in the current command context
        const DAPBreakpoint* bp = &server->current_command.context.breakpoint.breakpoints[i];
        mock_debugger.breakpoints[bp_idx].line = bp->line;
        mock_debugger.breakpoints[bp_idx].column = bp->column > 0 ? bp->column : 0;
        
        // Store source information
        mock_debugger.breakpoints[bp_idx].source_path = strdup(source_path);
        mock_debugger.breakpoints[bp_idx].source_name = strdup(source_name);
        
        // Copy over additional properties if they exist
        if (bp->condition) {
            mock_debugger.breakpoints[bp_idx].condition = strdup(bp->condition);
        }
        
        if (bp->hit_condition) {
            mock_debugger.breakpoints[bp_idx].hit_condition = strdup(bp->hit_condition);
        }
        
        if (bp->log_message) {
            mock_debugger.breakpoints[bp_idx].log_message = strdup(bp->log_message);
        }
        
        mock_debugger.breakpoint_count++;
        
        // Send console output about the new breakpoint
        char output_msg[256];
        snprintf(output_msg, sizeof(output_msg), "Added breakpoint %d at line %d in %s\n", 
                 mock_debugger.breakpoints[bp_idx].id,
                 mock_debugger.breakpoints[bp_idx].line,
                 source_name);
        dap_server_send_output_event(server, "console", output_msg);
        
        DBG_MOCK_LOG("Added breakpoint %d at line %d in %s", 
                  mock_debugger.breakpoints[bp_idx].id,
                  mock_debugger.breakpoints[bp_idx].line,
                  mock_debugger.breakpoints[bp_idx].source_path);
    }
    
    return 0;
}

/**
 * @brief Handler for the DAP 'launch' request command
 * 
 * The launch request is sent from the client to launch the debuggee with or without debugging.
 * This is the mock implementation that simulates program launch behavior.
 * 
 * According to DAP Specification:
 * - Required Parameters:
 *   - program: string - Path to the debuggee executable/script
 * - Optional Parameters:
 *   - stopOnEntry: boolean - Break at program entry point
 *   - noDebug: boolean - Launch without debugging features
 *   - args: array - Command line arguments for debuggee
 *   - cwd: string - Working directory for debuggee
 * 
 * Events Sequence:
 * 1. process: Indicates the debuggee process has started
 * 2. thread: Notifies that the main thread has started
 * 3. stopped: (If stopOnEntry=true) Indicates execution stopped at entry
 * 
 * State Management:
 * - Sets up initial debugger state for the launched program
 * - Configures source file mapping and debugging options
 * - Initializes program counter and execution context
 * - Prepares breakpoint handling if debugging is enabled
 * 
 * Error Handling:
 * - Validates required program path parameter
 * - Checks file existence and accessibility
 * - Verifies source file mappings if provided
 * 
 * @param server The DAP server instance containing the launch context
 * @return int 0 on success, non-zero on failure
 */
static int cmd_launch(DAPServer* server) {
    if (!server) {
        return -1;
    }
    
    DBG_MOCK_LOG("Launch command received");
    
    // Extract launch parameters directly from debugger state
    const char* program_path = server->debugger_state.program_path;
    const char* source_path = server->debugger_state.source_path;
    const char* map_path = server->debugger_state.map_path;
    bool stop_at_entry = server->debugger_state.stop_at_entry;
    bool no_debug = server->debugger_state.no_debug;
    
    // Log command line arguments if provided
    char** args = server->debugger_state.args;
    int args_count = server->debugger_state.args_count;
    
    if (!program_path) {
        DBG_MOCK_LOG("Error: Missing program path in debugger state");
        return -1;
    }
    
    DBG_MOCK_LOG("Launching program: %s", program_path ? program_path : "(null)");
    DBG_MOCK_LOG("Source path: %s", source_path ? source_path : "(not specified)");
    DBG_MOCK_LOG("Map file: %s", map_path ? map_path : "(not specified)");
    DBG_MOCK_LOG("Stop at entry: %s", stop_at_entry ? "yes" : "no");
    DBG_MOCK_LOG("No debug: %s", no_debug ? "yes" : "no");
    
    // Log command line arguments if present
    if (args && args_count > 0) {
        char arg_log[1024] = "Command line arguments:";
        size_t log_pos = strlen(arg_log);
        
        for (int i = 0; i < args_count && i < 10; i++) { // Limit to 10 args in log
            if (args[i]) {
                int written = snprintf(arg_log + log_pos, sizeof(arg_log) - log_pos, 
                                     " '%s'", args[i]);
                if (written > 0) {
                    log_pos += written;
                }
            }
        }
        
        if (args_count > 10) {
            snprintf(arg_log + log_pos, sizeof(arg_log) - log_pos, " ... (%d more)", 
                    args_count - 10);
        }
        
        DBG_MOCK_LOG("%s", arg_log);
    }
    
    // Reset the debugger state
    mock_debugger.pc = 0;
    mock_debugger.last_event = DAP_EVENT_INVALID;
    
    // Set debugger state
    server->is_running = true;
    server->attached = true;
    server->debugger_state.has_stopped = true;
    server->debugger_state.current_thread_id = 1; // make sure we have a thread id
    
    
    // TODO: Do something with the source_path and map_path
    
    // Send process event to indicate execution started
    dap_server_send_process_event(server, program_path, 1, true, "launch");
    
    // Send stopped event if stopAtEntry is true
    if (stop_at_entry) {
        dap_server_send_stopped_event(server, "entry", "Stopped at program entry");
        DBG_MOCK_LOG("Stopped at entry point");
    } else {
        // Send thread started event
        dap_server_send_thread_event(server, "started", 1);
    }
    
    DBG_MOCK_LOG("Launch command completed successfully");
    return 0; // Return success to ensure the response is properly set
}

/**
 * @brief Restart command handler for the mock debugger
 * 
 * This function implements the DAP restart command in the mock debugger. The restart
 * command allows a debug session to be restarted without disconnecting, which is
 * particularly useful for iterative debugging sessions.
 * 
 * Implementation Details:
 * - The mock debugger maintains minimal state (PC, source position, breakpoints)
 * - All state is reset to initial values during restart
 * - The original program path from the initial launch is preserved
 * - The noDebug option allows restarting without debugging capabilities
 * 
 * Event Sequence:
 * 1. terminated: Signals the end of the current debug session
 * 2. process: Indicates a new process has been created
 * 3. thread: Notifies that the main thread has started
 * 4. stopped: Indicates execution has stopped at the entry point
 * 
 * State Management:
 * - Program counter (PC) is reset to 0
 * - Source position is reset to line 1, column 1
 * - Debugger is placed in stopped state
 * - Last event is cleared
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_restart(DAPServer* server) {
    if (!server) {
        return -1;
    }
    
    // Notify the client that we're starting the restart process
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Restarting debuggee...\n");
    
    // Extract restart parameters from the command context
    // noDebug option allows restarting without debugging capabilities
    bool no_debug = server->current_command.context.restart.no_debug;
    
    // Log the restart action with the noDebug status
    DBG_MOCK_LOG("Handling restart command (noDebug: %s)", no_debug ? "true" : "false");
    
    // Verify we have a program to restart by checking the stored program path
    // This path should have been set during the initial launch
    const char* program_path = server->debugger_state.program_path;
    if (!program_path) {
        dap_server_send_output_category(server, DAP_OUTPUT_STDERR, "Error: No program to restart\n");
        DBG_MOCK_LOG("Cannot restart - no program_path in debugger state");
        return -1;
    }
    
    // Notify about terminating the current session
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Terminating current session...\n");
    
    // Reset all debugger state to initial values
    mock_debugger.pc = 0;  // Reset program counter
    mock_debugger.last_event = DAP_EVENT_INVALID;  // Clear last event
    
    // Reset source position and debugger state
    server->debugger_state.program_counter = 0;
    server->debugger_state.source_line = 1;
    server->debugger_state.source_column = 1;
    server->debugger_state.has_stopped = true;  // Start in stopped state
    
    // Notify about starting the new session
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Relaunching program...\n");
    
    // Send the sequence of events required for a proper restart:
    
    // 1. First, terminate the existing process
    // This notifies the client that the old process is ending
    dap_server_send_event(server, "terminated", NULL);
    
    // 2. Notify about the new process being created
    // The process event includes the program path and process ID
    dap_server_send_process_event(server, program_path, 1, true, "launch");
    
    // 3. Notify about the main thread starting
    // In this mock implementation, we always use thread ID 1
    dap_server_send_thread_event(server, "started", 1);
    
    // 4. Send stopped event at the entry point
    // This is where the debugger will initially stop after restart
    dap_server_send_stopped_event(server, "entry", "Stopped at program entry after restart");
    
    // Show detailed information about the restarted program
    char msg[256];
    snprintf(msg, sizeof(msg), "Program restarted: %s\n", program_path);
    dap_server_send_output_category(server, DAP_OUTPUT_IMPORTANT, msg);
    
    // If noDebug mode is enabled, warn the user that debugging features are disabled
    if (no_debug) {
        dap_server_send_output_category(server, DAP_OUTPUT_STDERR, 
                                      "Warning: Restarted in no-debug mode. Debugging features disabled.\n");
    }
    
    DBG_MOCK_LOG("Restart completed successfully");
    return 0;
}

/**
 * @brief Disconnect command handler
 * 
 * This function handles the disconnect command by:
 * 1. Cleaning up debug resources
 * 2. Optionally terminating the debuggee based on command parameters
 * 3. Sending appropriate events and messages to the client
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_disconnect(DAPServer* server) {
    if (!server) {
        return -1;
    }
    
    // Extract disconnect parameters from the command context
    bool terminate_debuggee = server->current_command.context.disconnect.terminate_debuggee;
    bool suspend_debuggee = server->current_command.context.disconnect.suspend_debuggee;
    bool restart = server->current_command.context.disconnect.restart;
    
    // Send appropriate output based on options
    if (restart) {
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Disconnecting for restart...\n");
    } else if (terminate_debuggee) {
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Disconnecting and terminating debuggee...\n");
    } else if (suspend_debuggee) {
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Disconnecting and suspending debuggee...\n");
    } else {
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Disconnecting from debuggee...\n");
    }
    
    // Log the disconnection with details
    DBG_MOCK_LOG("Handling disconnect command (terminate: %s, suspend: %s, restart: %s)",
               terminate_debuggee ? "true" : "false",
               suspend_debuggee ? "true" : "false",
               restart ? "true" : "false");
    
    // Clean up breakpoints
    if (mock_debugger.breakpoints) {
        for (int i = 0; i < mock_debugger.breakpoint_count; i++) {
            if (mock_debugger.breakpoints[i].source_path) {
                free(mock_debugger.breakpoints[i].source_path);
            }
            if (mock_debugger.breakpoints[i].source_name) {
                free(mock_debugger.breakpoints[i].source_name);
            }
            if (mock_debugger.breakpoints[i].condition) {
                free(mock_debugger.breakpoints[i].condition);
            }
            if (mock_debugger.breakpoints[i].hit_condition) {
                free(mock_debugger.breakpoints[i].hit_condition);
            }
            if (mock_debugger.breakpoints[i].log_message) {
                free(mock_debugger.breakpoints[i].log_message);
            }
        }
        
        free(mock_debugger.breakpoints);
        mock_debugger.breakpoints = NULL;
        mock_debugger.breakpoint_count = 0;
        mock_debugger.breakpoint_capacity = 0;
    }
    
    // If terminating, send terminated event
    if (terminate_debuggee && !restart) {
        cJSON *body = cJSON_CreateObject();
        if (body) {
            // The terminated event can optionally include a 'restart' attribute
            // but we don't need it here
            dap_server_send_event(server, "terminated", body);
        } else {
            dap_server_send_event(server, "terminated", NULL);
        }
        
        dap_server_send_output_category(server, DAP_OUTPUT_IMPORTANT, "Debuggee terminated.\n");
    }
    
    // Reset debugger state
    mock_debugger.pc = 0;
    mock_debugger.last_event = DAP_EVENT_INVALID;
    server->is_running = false;
    
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Disconnect complete.\n");
    DBG_MOCK_LOG("Disconnect completed successfully");
    
    return 0;
}

/**
 * @brief Disassemble command handler
 * 
 * This function handles the disassemble command by:
 * 1. Retrieving the memory reference, offset, and other parameters from the command context
 * 2. Generating mock disassembly data
 * 3. Formatting and sending the disassembly response
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_disassemble(DAPServer* server) {
    if (!server) {
        return -1;
    }
    
    // Extract parameters from the command context
    const char* memory_reference = server->current_command.context.disassemble.memory_reference;
    uint64_t offset = server->current_command.context.disassemble.offset;
    int instruction_offset = server->current_command.context.disassemble.instruction_offset;
    int instruction_count = server->current_command.context.disassemble.instruction_count;
    bool resolve_symbols = server->current_command.context.disassemble.resolve_symbols;
    
    if (!memory_reference) {
        DAP_SERVER_DEBUG_LOG("Missing memory reference for disassemble command");
        return -1;
    }
    
    // Log what we're disassembling
    DAP_SERVER_DEBUG_LOG("Disassembling memory reference: %s (offset: 0x%llx, count: %d, instruction_offset: %d)",
                      memory_reference, (unsigned long long)offset, instruction_count, instruction_offset);
    
    // Send console output indicating what we're disassembling
    char message[256];
    snprintf(message, sizeof(message), "Disassembling at %s + 0x%llx (%d instructions)...\n", 
             memory_reference, (unsigned long long)offset, instruction_count);
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, message);
    
    // Parse memory reference to get base address
    char* endptr = NULL;
    uint32_t address = (uint32_t)strtoul(memory_reference, &endptr, 0);
    if (endptr == memory_reference || *endptr != '\0') {
        dap_server_send_output_category(server, DAP_OUTPUT_STDERR, "Invalid memory reference format!\n");
        return -1;
    }
    
    // Apply byte offset
    address += (uint32_t)offset;
    
    // Create response body
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        dap_server_send_output_category(server, DAP_OUTPUT_STDERR, "Failed to create response body!\n");
        return -1;
    }
    
    // Create instructions array
    cJSON* instructions = cJSON_CreateArray();
    if (!instructions) {
        cJSON_Delete(body);
        dap_server_send_output_category(server, DAP_OUTPUT_STDERR, "Failed to create instructions array!\n");
        return -1;
    }
    
    // Mock instructions for ND-100 CPU
    // - A mock instruction set with 8 registers (R0-R7)
    // - Instruction size is 4 bytes
    // - Simple MOV, ADD, SUB, JMP instructions
    const char* opcodes[] = {
        "MOV", "ADD", "SUB", "JMP", "LDI", "STI", "CMP", "BNE", "BEQ", "BGT", "BLT"
    };
    int num_opcodes = sizeof(opcodes) / sizeof(opcodes[0]);
    
    // Generate disassembly
    uint32_t start_addr = address;
    // Apply instruction offset (each instruction is 4 bytes)
    if (instruction_offset > 0) {
        start_addr += (uint32_t)(instruction_offset * 4);
    }
    
    uint32_t current_addr = start_addr;
    char first_addr_str[16] = {0}; // Store the first address string for the completion message
    
    for (int i = 0; i < instruction_count; i++) {
        cJSON* instruction = cJSON_CreateObject();
        if (!instruction) {
            dap_server_send_output_category(server, DAP_OUTPUT_STDERR, "Failed to create instruction object!\n");
            cJSON_Delete(body);
            cJSON_Delete(instructions);
            return -1;
        }
        
        // Format address as hexadecimal
        char addr_str[16];
        snprintf(addr_str, sizeof(addr_str), "0x%04x", current_addr);
        
        // Store the first address for the completion message
        if (i == 0) {
            strncpy(first_addr_str, addr_str, sizeof(first_addr_str) - 1);
        }
        
        cJSON_AddStringToObject(instruction, "address", addr_str);
        
        // Generate a mock instruction based on the address
        const char* opcode = opcodes[current_addr % num_opcodes];
        int src_reg = (current_addr / 4) % 8;
        int dst_reg = ((current_addr / 4) + 1) % 8;
        
        char instr_text[32];
        if (strcmp(opcode, "JMP") == 0) {
            // Jump instructions use a single address
            snprintf(instr_text, sizeof(instr_text), "%s 0x%04x", opcode, current_addr + 16);
        } else if (strcmp(opcode, "BEQ") == 0 || strcmp(opcode, "BNE") == 0 || 
                   strcmp(opcode, "BGT") == 0 || strcmp(opcode, "BLT") == 0) {
            // Branch instructions compare a register and jump
            snprintf(instr_text, sizeof(instr_text), "%s R%d, 0x%04x", opcode, src_reg, current_addr + 8);
        } else {
            // Regular two-operand instructions
            snprintf(instr_text, sizeof(instr_text), "%s R%d, R%d", opcode, dst_reg, src_reg);
        }
        
        cJSON_AddStringToObject(instruction, "instruction", instr_text);
        
        // Add symbol information if requested
        if (resolve_symbols) {
            // Generate mock symbol information based on address
            if (current_addr % 32 == 0) {
                char symbol[32];
                snprintf(symbol, sizeof(symbol), "function_%04x", current_addr);
                cJSON_AddStringToObject(instruction, "symbol", symbol);
            }
        }
        
        // Add to instructions array
        cJSON_AddItemToArray(instructions, instruction);
        
        // Move to next instruction (4 bytes per instruction in this architecture)
        current_addr += 4;
    }
    
    // Attach instructions array to response body
    cJSON_AddItemToObject(body, "instructions", instructions);
    
    // Generate response JSON
    char* response_str = cJSON_Print(body);
    if (response_str) {
        // In a callback implementation, we don't need to set response fields directly
        // Instead, the handler in dap_server_cmds.c will take care of that
        // Just log some debugging information and free our temporary string
        DAP_SERVER_DEBUG_LOG("Generated disassembly response of %zu bytes", strlen(response_str));
        free(response_str);
    }
    
    // Free the response body - the disassemble handler will generate its own response
    cJSON_Delete(body);
    
    // Send a human-friendly completion message
    snprintf(message, sizeof(message), "Disassembly complete: %d instructions starting at %s.\n", 
             instruction_count, first_addr_str);
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, message);
    
    return 0;
}

/**
 * @brief Scopes command handler
 * 
 * This function handles the scopes command by:
 * 1. Retrieving the frame_id from the command context
 * 2. Creating DAPScope structures for each available scope
 * 3. Storing the scopes in the server context for the DAP server to handle
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_scopes(DAPServer *server) {
    if (!server) {
        return -1;
    }
    
    DBG_MOCK_LOG("Handling scopes command");
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Retrieving scopes...\n");
    
    // Extract frame_id from the command context
    int frame_id = server->current_command.context.scopes.frame_id;
    
    DBG_MOCK_LOG("Frame ID: %d", frame_id);
    
    // Allocate memory for the scopes
    const int NUM_SCOPES = 3; // Locals, Registers, Memory (CPU Flags is a subtype under STS register)
    DAPScope* scopes = (DAPScope*)calloc(NUM_SCOPES, sizeof(DAPScope));
    if (!scopes) {
        DBG_MOCK_LOG("Failed to allocate memory for scopes");
        dap_server_send_output_category(server, DAP_OUTPUT_STDERR, "Error: Failed to allocate memory for scopes\n");
        return -1;
    }
    
    // Set up Locals scope
    int scope_index = 0;
    scopes[scope_index].name = strdup("Locals");
    scopes[scope_index].variables_reference = SCOPE_ID_LOCALS;
    scopes[scope_index].named_variables = 5; // Number of local variables
    scopes[scope_index].indexed_variables = 0;
    scopes[scope_index].expensive = false;
    // Source location fields are optional, set to 0/NULL
    scopes[scope_index].source_path = NULL;
    scopes[scope_index].line = 0;
    scopes[scope_index].column = 0;
    scopes[scope_index].end_line = 0;
    scopes[scope_index].end_column = 0;
    
    // Set up CPU Registers scope
    scope_index++;
    scopes[scope_index].name = strdup("CPU Registers");
    scopes[scope_index].variables_reference = SCOPE_ID_REGISTERS;
    scopes[scope_index].named_variables = NUM_REGISTERS;
    scopes[scope_index].indexed_variables = 0;
    scopes[scope_index].expensive = false;
    // Source location fields are optional, set to 0/NULL
    scopes[scope_index].source_path = NULL;
    scopes[scope_index].line = 0;
    scopes[scope_index].column = 0;
    scopes[scope_index].end_line = 0;
    scopes[scope_index].end_column = 0;
    
    // Set up Memory scope
    scope_index++;
    scopes[scope_index].name = strdup("Memory");
    scopes[scope_index].variables_reference = SCOPE_ID_MEMORY;
    scopes[scope_index].named_variables = 3; // Number of memory regions
    scopes[scope_index].indexed_variables = 0;
    scopes[scope_index].expensive = true; // Memory access is expensive
    // Source location fields are optional, set to 0/NULL
    scopes[scope_index].source_path = NULL;
    scopes[scope_index].line = 0;
    scopes[scope_index].column = 0;
    scopes[scope_index].end_line = 0;
    scopes[scope_index].end_column = 0;
    
    // Store the scopes in the command context for the DAP server to use
    server->current_command.context.scopes.scopes = scopes;
    server->current_command.context.scopes.scope_count = NUM_SCOPES;
    
    return 0;
}

/**
 * @brief Helper function to add a variable to the server's variable array
 * 
 * @param server The DAP server instance
 * @param name Variable name
 * @param value Variable value
 * @param type Variable type
 * @param variables_reference Reference for child variables (0 for leaf variables)
 * @param memory_reference Optional memory reference
 * @param kind Variable kind (property, method, etc.)
 * @param attributes Array of attribute flags
 * @return DAPVariable* Pointer to the newly added variable or NULL on failure
 */
static DAPVariable* add_variable_to_array(
    DAPServer *server,
    const char* name,
    const char* value,
    const char* type,
    int variables_reference,
    const char* memory_reference,
    const char* kind,
    const char** attributes,
    int num_attributes
) {
    if (!server || !name || !value) {
        return NULL;
    }
    
    // Increase the count and reallocate the array
    server->current_command.context.variables.count++;
    server->current_command.context.variables.variable_array = realloc(
        server->current_command.context.variables.variable_array, 
        server->current_command.context.variables.count * sizeof(DAPVariable)
    );
    
    if (!server->current_command.context.variables.variable_array) {
        server->current_command.context.variables.count--;
        return NULL;
    }
    
    // Get a pointer to the newly added variable
    DAPVariable* var = &server->current_command.context.variables.variable_array[
        server->current_command.context.variables.count - 1
    ];
    
    // Initialize the variable with the provided values
    if (name)
        var->name = strdup(name);
    else
        var->name = NULL;
        
    if (value)
        var->value = strdup(value);
    else
        var->value = NULL;
        
    if (type)
        var->type = strdup(type);
    else
        var->type = NULL;
        
    var->variables_reference = variables_reference;
    var->named_variables = 0;
    var->indexed_variables = 0;
    var->evaluate_name = NULL;
    
    if (memory_reference)
        var->memory_reference = strdup(memory_reference);
    else
        var->memory_reference = NULL;
    
    // Handle presentation hint
    // Default initialization
    var->presentation_hint.has_kind = false;
    var->presentation_hint.has_visibility = false;
    var->presentation_hint.attributes = DAP_VARIABLE_ATTR_NONE;
    
    // Set kind if provided
    if (kind && kind[0] != '\0') {
        var->presentation_hint.has_kind = true;
        
        // Map string kind to enum
        if (strcmp(kind, "property") == 0) {
            var->presentation_hint.kind = DAP_VARIABLE_KIND_PROPERTY;
        } else if (strcmp(kind, "method") == 0) {
            var->presentation_hint.kind = DAP_VARIABLE_KIND_METHOD;
        } else if (strcmp(kind, "class") == 0) {
            var->presentation_hint.kind = DAP_VARIABLE_KIND_CLASS;
        } else if (strcmp(kind, "data") == 0) {
            var->presentation_hint.kind = DAP_VARIABLE_KIND_DATA;
        } else if (strcmp(kind, "event") == 0) {
            var->presentation_hint.kind = DAP_VARIABLE_KIND_EVENT;
        } else if (strcmp(kind, "baseClass") == 0) {
            var->presentation_hint.kind = DAP_VARIABLE_KIND_BASE_CLASS;
        } else if (strcmp(kind, "innerClass") == 0) {
            var->presentation_hint.kind = DAP_VARIABLE_KIND_INNER_CLASS;
        } else if (strcmp(kind, "interface") == 0) {
            var->presentation_hint.kind = DAP_VARIABLE_KIND_INTERFACE;
        } else if (strcmp(kind, "mostDerived") == 0) {
            var->presentation_hint.kind = DAP_VARIABLE_KIND_MOST_DERIVED;
        } else if (strcmp(kind, "virtual") == 0) {
            var->presentation_hint.kind = DAP_VARIABLE_KIND_VIRTUAL;
        } else if (strcmp(kind, "dataBreakpoint") == 0) {
            var->presentation_hint.kind = DAP_VARIABLE_KIND_DATABREAKPOINT;
        } else {
            // Unknown kind
            var->presentation_hint.has_kind = false;
        }
    }
    
    // Set attributes if provided
    if (attributes && num_attributes > 0) {
        for (int i = 0; i < num_attributes; i++) {
            if (!attributes[i]) continue;
            
            if (strcmp(attributes[i], "static") == 0) {
                var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_STATIC;
            } else if (strcmp(attributes[i], "constant") == 0) {
                var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_CONSTANT;
            } else if (strcmp(attributes[i], "readOnly") == 0) {
                var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_READONLY;
            } else if (strcmp(attributes[i], "rawString") == 0) {
                var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_RAWSTRING;
            } else if (strcmp(attributes[i], "hasObjectId") == 0) {
                var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_HASOBJECTID;
            } else if (strcmp(attributes[i], "canHaveObjectId") == 0) {
                var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_CANHAVEOBJECTID;
            } else if (strcmp(attributes[i], "hasSideEffects") == 0) {
                var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_HASSIDEEFFECTS;
            } else if (strcmp(attributes[i], "hasDataBreakpoint") == 0) {
                var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_HASDATABREAKPOINT;
            } else if (strcmp(attributes[i], "hasChildren") == 0) {
                var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_HASCHILDREN;
            }
        }
    }
    
    return var;
}

/**
 * @brief Add local variables to the variables array
 * 
 * @param server The DAP server instance
 * @param info_message Buffer to write info message
 * @param info_message_size Size of info message buffer 
 */
static void add_local_variables(DAPServer *server, char* info_message, size_t info_message_size) {
    snprintf(info_message, info_message_size, 
             "Loading local variables (showing typical counter, flag, and string variables)\n");
    
    // Property kind for all variables
    const char* property_kind = "property";
    const char* no_attributes[] = {NULL};
    
    // Add counter variable
    add_variable_to_array(
        server,
        "counter",     // name
        "42",          // value
        "integer",     // type
        0,             // variablesReference
        NULL,          // memoryReference
        property_kind, // kind
        no_attributes, // attributes
        0              // num_attributes
    );
    
    // Add flag variable
    add_variable_to_array(
        server,
        "isEnabled",   // name
        "true",        // value
        "boolean",     // type
        0,             // variablesReference
        NULL,          // memoryReference
        property_kind, // kind
        no_attributes, // attributes
        0              // num_attributes
    );
    
    // Add string variable
    add_variable_to_array(
        server,
        "message",     // name
        "\"Hello, DAP!\"", // value
        "string",      // type
        0,             // variablesReference
        NULL,          // memoryReference
        property_kind, // kind
        no_attributes, // attributes
        0              // num_attributes
    );
}

/**
 * @brief Add register variables to the variables array
 * 
 * @param server The DAP server instance
 * @param info_message Buffer to write info message
 * @param info_message_size Size of info message buffer
 */
static void add_register_variables(DAPServer *server, char* info_message, size_t info_message_size) {
    snprintf(info_message, info_message_size, 
             "Loading CPU registers (A, B, X, P, S, D, L, T)\n");
    
    // Property kind with readonly attribute
    const char* property_kind = "property";
    const char* readonly_attrs[] = {"readOnly"};
    
    // Add each register
    for (size_t i = 0; i < NUM_REGISTERS; i++) {
        // Format value based on type
        char value_str[32];
        if (strcmp(cpu_registers[i].type, "integer") == 0) {
            snprintf(value_str, sizeof(value_str), "0x%04X", cpu_registers[i].value);
        } else if (strcmp(cpu_registers[i].type, "bitmask") == 0) {
            snprintf(value_str, sizeof(value_str), "0b%04X", cpu_registers[i].value);
        } else {
            snprintf(value_str, sizeof(value_str), "%o", cpu_registers[i].value);
        }
        
        // Create memory reference
        char mem_ref[32];
        snprintf(mem_ref, sizeof(mem_ref), "0x%04X", (int)(i * 2));
        
        // Add register
        add_variable_to_array(
            server,
            cpu_registers[i].name, // name
            value_str,             // value
            cpu_registers[i].type, // type
            cpu_registers[i].has_nested ? cpu_registers[i].nested_ref : 0, // varsRef
            mem_ref,               // memoryReference
            property_kind,         // kind
            readonly_attrs,        // attributes
            1                      // num_attributes
        );
    }
}

/**
 * @brief Add status flag variables to the variables array
 * 
 * @param server The DAP server instance
 * @param info_message Buffer to write info message
 * @param info_message_size Size of info message buffer
 */
static void add_status_flag_variables(DAPServer *server, char* info_message, size_t info_message_size) {
    snprintf(info_message, info_message_size, 
             "Loading CPU status flags\n");
    
    // Property kind with readonly attribute
    const char* property_kind = "property";
    const char* readonly_attrs[] = {"readOnly"};
    
    // Add each flag from the status_flags array
    for (size_t i = 0; i < NUM_STATUS_FLAGS; i++) {
        // Create variable
        add_variable_to_array(
            server,
            status_flags[i].name,              // name
            status_flags[i].value ? "true" : "false", // value
            status_flags[i].type,              // type
            0,                                 // variablesReference
            NULL,                              // memoryReference
            property_kind,                     // kind
            readonly_attrs,                    // attributes
            1                                  // num_attributes
        );
    }
}

/**
 * @brief Add memory region variables to the variables array
 * 
 * @param server The DAP server instance
 * @param info_message Buffer to write info message
 * @param info_message_size Size of info message buffer
 */
static void add_memory_region_variables(DAPServer *server, char* info_message, size_t info_message_size) {
    snprintf(info_message, info_message_size, 
             "Loading memory regions (Stack: 0x0000-0x1FFF, Heap: 0x2000-0x4FFF, Code: 0x5000-0xFFFF)\n");
    
    // Add memory region variables
    const char *regions[] = {"Stack", "Heap", "Code"};
    const char *ranges[] = {"0x0000-0x1FFF", "0x2000-0x4FFF", "0x5000-0xFFFF"};
    const char *mem_refs[] = {"0x0000", "0x2000", "0x5000"};
    
    // Property kind - readonly
    const char* property_kind = "property";
    const char* no_attributes[] = {NULL};
    
    for (int i = 0; i < 3; i++) {
        add_variable_to_array(
            server,
            regions[i],        // name
            ranges[i],         // value
            "memory",          // type
            0,                 // variablesReference
            mem_refs[i],       // memoryReference
            property_kind,     // kind
            no_attributes,     // attributes
            0                  // num_attributes
        );
    }
}

/**
 * @brief Initialize the mock debugger with the specified port
 * 
 * @param port TCP port to listen on for DAP connections
 * @return int 0 on success, non-zero on failure
 */
int dbg_mock_init(int port) {
    // Initialize mock debugger state
    mock_debugger.pc = 0;
    mock_debugger.last_event = DAP_EVENT_INVALID;
    mock_debugger.memory_size = 0;
    mock_debugger.memory = NULL;
    mock_debugger.register_count = 0;
    mock_debugger.registers = NULL;
    mock_debugger.exception_filters = NULL;
    mock_debugger.exception_filter_count = 0;
    
    // Initialize breakpoint state
    mock_debugger.breakpoints = NULL;
    mock_debugger.breakpoint_count = 0;
    mock_debugger.breakpoint_capacity = 0;

    // Initialize DAP server
    DAPServerConfig config = {
        .transport = {
            .type = DAP_TRANSPORT_TCP,
            .config = {
                .tcp = {
                    .host = "localhost",
                    .port = port
                }
            }
        }
    };

    mock_debugger.server = dap_server_create(&config);
    if (!mock_debugger.server) {
        return -1;
    }

    // Set up callbacks and capabilities using the new helper function
    if (setup_server_callbacks(mock_debugger.server) != 0) {
        dap_server_free(mock_debugger.server);
        mock_debugger.server = NULL;
        return -1;
    }

    return 0;
}

int dbg_mock_start(void) {
    if (!mock_debugger.server) {
        return -1;
    }
    
    int result = dap_server_start(mock_debugger.server);
    if (result != 0) {
        return result;
    }
    
    // Set up a hook to detect when a client connects
    // The original transport accept function accepts the connection
    DAPTransport *transport = mock_debugger.server->transport;
    int original_accept_fd = transport->client_fd;
    
    // Monitor for client connections in a non-blocking way
    mock_debugger.client_connected = false;
    
    return result;
}

void dbg_mock_stop(void) {
    if (mock_debugger.server) {
        dap_server_stop(mock_debugger.server);
    }
}

void dbg_mock_cleanup(void) {
    if (mock_debugger.server) {
        dap_server_free(mock_debugger.server);
        mock_debugger.server = NULL;
    }
    
    if (mock_debugger.memory) {
        free(mock_debugger.memory);
        mock_debugger.memory = NULL;
    }
    
    if (mock_debugger.registers) {
        free(mock_debugger.registers);
        mock_debugger.registers = NULL;
    }
    
    // Free breakpoints
    if (mock_debugger.breakpoints) {
        for (int i = 0; i < mock_debugger.breakpoint_count; i++) {
            free(mock_debugger.breakpoints[i].source_path);
            free(mock_debugger.breakpoints[i].source_name);
            
            if (mock_debugger.breakpoints[i].condition) {
                free(mock_debugger.breakpoints[i].condition);
            }
            if (mock_debugger.breakpoints[i].hit_condition) {
                free(mock_debugger.breakpoints[i].hit_condition);
            }
            if (mock_debugger.breakpoints[i].log_message) {
                free(mock_debugger.breakpoints[i].log_message);
            }
        }
        free(mock_debugger.breakpoints);
        mock_debugger.breakpoints = NULL;
    }
    mock_debugger.breakpoint_count = 0;
    mock_debugger.breakpoint_capacity = 0;
    
    // Free exception filters
    if (mock_debugger.exception_filters) {
        for (size_t i = 0; i < mock_debugger.exception_filter_count; i++) {
            free(mock_debugger.exception_filters[i].filter_id);
            free(mock_debugger.exception_filters[i].condition);
        }
        free(mock_debugger.exception_filters);
        mock_debugger.exception_filters = NULL;
    }
    mock_debugger.exception_filter_count = 0;
}


static int init_debugger_state(DAPServer *server) {
    if (!server) {
        return -1;
    }
    
    // Initialize the debugger_state fields
    server->debugger_state.program_counter = 0;
    server->debugger_state.source_line = 1;  // Start at line 1
    server->debugger_state.source_column = 1;
    server->debugger_state.has_stopped = true;  // Start in stopped state
    server->debugger_state.stop_reason = NULL;
    server->debugger_state.stop_description = NULL;
    server->debugger_state.current_thread_id = 1;  // Default thread ID
    
    // Program information initially empty
    server->debugger_state.program_path = NULL;
    server->debugger_state.source_path = NULL;
    server->debugger_state.map_path = NULL;
    server->debugger_state.working_directory = NULL;
    server->debugger_state.no_debug = false;
    server->debugger_state.stop_at_entry = true;
    
    // Command line arguments
    server->debugger_state.args = NULL;
    server->debugger_state.args_count = 0;
    
    // User data
    server->debugger_state.user_data = NULL;
    
    return 0;
}


/**
 * @brief Mock debugger's implementation of initialize command
 * 
 * This callback is called by the DAP server after protocol-level handling of initialize.
 * It sets up the mock debugger's state and capabilities for a new debug session.
 * 
 * Responsibilities:
 * 1. Set supported debug features via capabilities
 * 2. Initialize mock debugger state (memory, registers, etc)
 * 3. Prepare for subsequent commands
 * 
 * Capabilities advertised by mock debugger:
 * - Basic execution control (continue, step, pause)
 * - Breakpoint support (source lines, functions, conditions)
 * - Variable inspection and modification
 * - Memory access (read/write)
 * - Stack trace and scope information
 * - Exception handling
 * 
 * State initialization:
 * - Clears breakpoint list
 * - Resets execution state
 * - Initializes mock memory and registers
 * - Sets up exception filters
 * 
 * Events generated:
 * - None directly (initialized event sent by server)
 * 
 * Error handling:
 * - Returns non-zero if initialization fails
 * - Logs detailed error via DBG_MOCK_LOG
 * 
 * @param server The DAP server instance
 * @return 0 on success, non-zero on failure
 */
int dbg_mock_set_default_capabilities(DAPServer *server) {
    if (!server) {
        return -1;
    }
    
    DBG_MOCK_LOG("Setting up default capabilities for mock server");
    
    return dap_server_set_capabilities(server,
        // These capabilities are fully implemented in the mock server
        DAP_CAP_CONFIG_DONE_REQUEST, true,
        DAP_CAP_EVALUATE_FOR_HOVERS, true,
        DAP_CAP_RESTART_REQUEST, true,
        DAP_CAP_TERMINATE_REQUEST, true,
        DAP_CAP_TERMINATE_DEBUGGEE, true,  // Support disconnect with terminateDebuggee option
        DAP_CAP_DISASSEMBLE_REQUEST, true, // Support for disassemble command
        DAP_CAP_SINGLE_THREAD_EXECUTION_REQUESTS, true, // Support for thread-specific execution control
        DAP_CAP_READ_MEMORY_REQUEST, true, // Support for readMemory
        DAP_CAP_SET_VARIABLE, true,        // Support for variables
        DAP_CAP_VALUE_FORMATTING_OPTIONS, true, // Support for formatting options in variables
        DAP_CAP_DISASSEMBLE_REQUEST, true, // Support for disassemble command
        DAP_CAP_COUNT  // Terminator
    );
}



/**
 * @brief Register command callbacks for mock debugger implementation
 * 
 * This function connects the mock debugger's command implementations to the DAP server.
 * Each callback implements the debugger-specific behavior for a DAP command.
 * 
 * For initialize:
 * - Sets default capabilities via dbg_mock_set_default_capabilities()
 * - No direct initialize callback needed - capabilities setup is sufficient
 * 
 * Command callback sequence:
 * 1. DAP server receives command
 * 2. Server validates protocol requirements
 * 3. Server calls registered callback if present
 * 4. Callback implements debugger-specific behavior
 * 5. Server handles response and event generation
 * 
 * @param server The DAP server instance
 * @return 0 on success, -1 on failure
 */
int setup_server_callbacks(DAPServer *server) {
    if (!server) {
        return -1;
    }

    DBG_MOCK_LOG("Initializing mock debugger");

    // Set up default capabilities
    dbg_mock_set_default_capabilities(server);

    // Register command callbacks
    dap_server_register_command_callback(server, DAP_CMD_NEXT, cmd_next);
    dap_server_register_command_callback(server, DAP_CMD_STEP_IN, cmd_step_in);
    dap_server_register_command_callback(server, DAP_CMD_STEP_OUT, cmd_step_out);
    dap_server_register_command_callback(server, DAP_CMD_CONTINUE, cmd_continue);
    dap_server_register_command_callback(server, DAP_CMD_READ_MEMORY, cmd_read_memory);
    dap_server_register_command_callback(server, DAP_CMD_WRITE_MEMORY, cmd_write_memory);
    dap_server_register_command_callback(server, DAP_CMD_SCOPES, cmd_scopes);
    dap_server_register_command_callback(server, DAP_CMD_VARIABLES, cmd_variables);
    dap_server_register_command_callback(server, DAP_CMD_EXCEPTION_INFO, on_set_exception_breakpoints);
    dap_server_register_command_callback(server, DAP_CMD_SET_BREAKPOINTS, cmd_set_breakpoints);
    dap_server_register_command_callback(server, DAP_CMD_LAUNCH, cmd_launch);
    dap_server_register_command_callback(server, DAP_CMD_RESTART, cmd_restart);
    dap_server_register_command_callback(server, DAP_CMD_SET_VARIABLE, &cmd_set_variable);
    dap_server_register_command_callback(server, DAP_CMD_STACK_TRACE, mock_handle_stack_trace);

    // Initialize debugger state
    init_debugger_state(server);

    return 0;
}

/**
 * @brief Variables command handler
 * 
 * This function handles the variables command by:
 * 1. Getting the variables reference from the command context
 * 2. Populating a variables array based on the reference type
 * 3. Sending the response back to the client
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_variables(DAPServer *server) {
    if (!server) {
        return -1;
    }
    
    DBG_MOCK_LOG("Handling variables command");
    
    // Extract variables reference from the command context
    int variables_reference = server->current_command.context.variables.variables_reference;
    DBG_MOCK_LOG("Variables reference: %d", variables_reference);
    
    // Buffer for informational messages
    char info_message[256] = {0};
    

    // Handle different variable reference types
    switch (variables_reference) {
        case SCOPE_ID_LOCALS: {
            // Use our helper function for local variables
            add_local_variables(server, info_message, sizeof(info_message));
            break;
        }
        
        case SCOPE_ID_REGISTERS: {
            // Use our helper function for register variables
            add_register_variables(server, info_message, sizeof(info_message));
            break;
        }
        
        case SCOPE_ID_STATUS_FLAGS: {
            // Use our helper function for status flag variables
            add_status_flag_variables(server, info_message, sizeof(info_message));
            break;
        }
   
         
        case SCOPE_ID_MEMORY: {
            // Use our helper function for memory region variables
            add_memory_region_variables(server, info_message, sizeof(info_message));
            break;
        }
            
        default:
            dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Unknown variable reference\n");
            break;
    }
    
    // Output info message if we have one
    if (info_message[0] != '\0') {
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, info_message);
    }
       
    return 0;
}


/**
 * @brief Set Variable command handler
 * 
 * This function handles the setVariable command by:
 * 1. Extracting the variable parameters from the command context
 * 2. Updating the variable value in our mock state
 * 3. Sending a response with the updated variable
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_set_variable(DAPServer *server)
{
    if (!server) {
        return -1;
    }
    
    // Extract parameters from command context
    int variables_reference = server->current_command.context.set_variable.variables_reference;
    const char* name = server->current_command.context.set_variable.name;
    const char* value = server->current_command.context.set_variable.value;
    
    DBG_MOCK_LOG("Handling setVariable command for %s = %s in container %d", 
               name ? name : "(null)", value ? value : "(null)", variables_reference);
    
    // Validate required parameters
    if (!name || !value) {
        dap_server_send_output_category(server, DAP_OUTPUT_STDERR, 
                                     "Error: Missing name or value for setVariable\n");
        return -1;
    }
    
    // Prepare response body
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        dap_server_send_output_category(server, DAP_OUTPUT_STDERR,
                                     "Error: Failed to create response body\n");
        return -1;
    }
    
    // Add basic fields to response that will be common for all variables
    cJSON_AddStringToObject(body, "value", value);
    cJSON_AddStringToObject(body, "type", "");  // Will be updated based on container
    cJSON_AddNumberToObject(body, "variablesReference", 0);
    
    // Variable information to show in console
    char info_message[256];
    bool variable_found = false;
    
    // Handle different variable containers
    switch (variables_reference) {
        case SCOPE_ID_LOCALS: {
            // Handle local variables
            snprintf(info_message, sizeof(info_message), 
                     "Setting local variable '%s' to %s\n", name, value);
            
            // Just accept all local variables in the mock
            variable_found = true;
            
            // Determine type based on value format
            const char* type = "string";
            if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0) {
                type = "boolean";
            } else if (isdigit((unsigned char)value[0]) || 
                       (value[0] == '-' && isdigit((unsigned char)value[1]))) {
                type = "integer";
            } else if (value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
                type = "integer";
            }
            
            // Update type in response
            cJSON_AddStringToObject(body, "type", type);
            
            dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, info_message);
            break;
        }
        
        case SCOPE_ID_REGISTERS: {
            // Handle register variables
            snprintf(info_message, sizeof(info_message), 
                     "Setting register '%s' to %s\n", name, value);
            
            // Find the register by name
            for (size_t i = 0; i < NUM_REGISTERS; i++) {
                if (strcmp(name, cpu_registers[i].name) == 0) {
                    // Parse the value based on register type
                    if (strcmp(cpu_registers[i].type, "integer") == 0) {
                        // Handle hex values (0x...) and decimal values
                        if (strncmp(value, "0x", 2) == 0 || strncmp(value, "0X", 2) == 0) {
                            cpu_registers[i].value = (int)strtol(value, NULL, 16);
                        } else {
                            cpu_registers[i].value = atoi(value);
                        }
                    } else if (strcmp(cpu_registers[i].type, "bitmask") == 0) {
                        // Handle binary (0b...), octal (0...), and hex (0x...)
                        if (strncmp(value, "0b", 2) == 0 || strncmp(value, "0B", 2) == 0) {
                            cpu_registers[i].value = (int)strtol(value + 2, NULL, 2);
                        } else if (strncmp(value, "0x", 2) == 0 || strncmp(value, "0X", 2) == 0) {
                            cpu_registers[i].value = (int)strtol(value, NULL, 16);
                        } else if (value[0] == '0') {
                            cpu_registers[i].value = (int)strtol(value, NULL, 8);
                        } else {
                            cpu_registers[i].value = atoi(value);
                        }
                    } else {
                        // Octal format by default
                        cpu_registers[i].value = (int)strtol(value, NULL, 8);
                    }
                    
                    variable_found = true;
                    cJSON_AddStringToObject(body, "type", cpu_registers[i].type);
                    
                    // Format the value for display according to register type
                    char formatted_value[32];
                    if (strcmp(cpu_registers[i].type, "integer") == 0) {
                        snprintf(formatted_value, sizeof(formatted_value), "0x%04X", cpu_registers[i].value);
                    } else if (strcmp(cpu_registers[i].type, "bitmask") == 0) {
                        snprintf(formatted_value, sizeof(formatted_value), "0b%04X", cpu_registers[i].value);
                    } else {
                        snprintf(formatted_value, sizeof(formatted_value), "%o", cpu_registers[i].value);
                    }
                    cJSON_DeleteItemFromObject(body, "value");
                    cJSON_AddStringToObject(body, "value", formatted_value);
                    
                    break;
                }
            }
            
            dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, info_message);
            break;
        }
        
        default:
            snprintf(info_message, sizeof(info_message), 
                     "Unknown variable container %d\n", variables_reference);
            dap_server_send_output_category(server, DAP_OUTPUT_STDERR, info_message);
            variable_found = false;
            break;
    }
    
    if (!variable_found) {
        dap_server_send_output_category(server, DAP_OUTPUT_STDERR, 
                                     "Error: Variable not found\n");
        cJSON_Delete(body);
        return -1;
    }
    
    // Send the response with the updated variable information
    dap_server_send_response(server, DAP_CMD_SET_VARIABLE, server->sequence++, 
                          server->current_command.request_seq, true, body);
    
    // Clean up
    cJSON_Delete(body);
    
    return 0;
}