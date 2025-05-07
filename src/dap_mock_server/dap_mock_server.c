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
#include <cjson/cJSON.h>
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
 * 4. Setting up a response with the data in base64 encoding
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
        return -1;
    }
    
    // Apply offset to address
    address += (uint32_t)offset;
    
    // Ensure the address is within range
    if (address >= sizeof(mock_memory)) {
        DBG_MOCK_LOG("Address out of range: 0x%x", address);
        return -1;
    }
    
    // Determine how many bytes we can actually read
    size_t available_bytes = sizeof(mock_memory) - address;
    size_t bytes_to_read = (count <= available_bytes) ? count : available_bytes;
    size_t unreadable_bytes = count - bytes_to_read;
    
    // Create a copy of the data to send (we don't want to modify our mock memory)
    uint8_t* data = malloc(bytes_to_read);
    if (!data) {
        DBG_MOCK_LOG("Failed to allocate memory for data");
        return -1;
    }
    
    // Copy the data from mock memory
    memcpy(data, &mock_memory[address], bytes_to_read);
    
    // Format address as a string (per DAP spec)
    char address_str[32];
    snprintf(address_str, sizeof(address_str), "0x%08x", address);
    
    // Create response body
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        free(data);
        DBG_MOCK_LOG("Failed to create response body");
        return -1;
    }
    
    // Add address to response
    cJSON_AddStringToObject(body, "address", address_str);
    
    // Add unreadableBytes if any
    if (unreadable_bytes > 0) {
        cJSON_AddNumberToObject(body, "unreadableBytes", (int)unreadable_bytes);
        DBG_MOCK_LOG("Some bytes were unreadable: %zu", unreadable_bytes);
    }
    
    // Convert data to base64 using DAP server's base64_encode function
    char* encoded = NULL;
    if (bytes_to_read > 0) {
        // We can't directly call the base64_encode function from dap_server_cmds.c
        // because it's static, so we'll have to rely on the library's encoder
        // For this mock implementation, we'll simulate the encoding with a simple approach
        
        // Allocate memory for base64 (4 chars for every 3 bytes plus padding)
        size_t encoded_len = 4 * ((bytes_to_read + 2) / 3) + 1; // +1 for null terminator
        encoded = malloc(encoded_len);
        if (encoded) {
            // Simple implementation for common hex chars
            char* p = encoded;
            for (size_t i = 0; i < bytes_to_read; i++) {
                snprintf(p, 3, "%02x", data[i]);
                p += 2;
            }
            *p = '\0';
        }
    }
    
    if (encoded) {
        cJSON_AddStringToObject(body, "data", encoded);
        free(encoded);
    } else {
        cJSON_AddStringToObject(body, "data", "");
        DBG_MOCK_LOG("Failed to encode data as base64");
    }
    
    free(data);
    
    // Set the response
    DAPResponse response = {0};
    response.success = true;
    response.data = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    
    if (!response.data) {
        DBG_MOCK_LOG("Failed to format response body");
        return -1;
    }
    
    // Send the response
    int seq = server->current_command.request_seq;
    int result = dap_server_send_response(server, DAP_CMD_READ_MEMORY, server->sequence++, seq, true, cJSON_Parse(response.data));
    
    free(response.data);
    
    return (result == 0) ? 0 : -1;
}

/*** CALLBACKS ***/

// Command callback wrappers (these match the DAPCommandCallback signature)
static int cmd_next(DAPServer *server) {
    // Use the step context that was populated by the protocol handler
    int thread_id = server->current_command.context.step.thread_id;
    // Extract granularity from the context
    StepGranularity granularity = DAP_STEP_GRANULARITY_STATEMENT;
    if (server->current_command.context.step.granularity) {
        if (strcmp(server->current_command.context.step.granularity, "instruction") == 0) {
            granularity = DAP_STEP_GRANULARITY_INSTRUCTION;
        } else if (strcmp(server->current_command.context.step.granularity, "line") == 0) {
            granularity = DAP_STEP_GRANULARITY_LINE;
        }
    }
    

    // TODO: Implement step in
    mock_debugger.pc++;

    server->debugger_state.program_counter = mock_debugger.pc;
    server->debugger_state.source_line++;

    return 0;    

}

static int cmd_step_in(DAPServer *server) {
    // Use the step context that was populated by the protocol handler
    int thread_id = server->current_command.context.step.thread_id;
    int target_id = server->current_command.context.step.target_id;
    // Extract granularity from the context
    StepGranularity granularity = DAP_STEP_GRANULARITY_INSTRUCTION;
    if (server->current_command.context.step.granularity) {
        if (strcmp(server->current_command.context.step.granularity, "statement") == 0) {
            granularity = DAP_STEP_GRANULARITY_STATEMENT;
        } else if (strcmp(server->current_command.context.step.granularity, "line") == 0) {
            granularity = DAP_STEP_GRANULARITY_LINE;
        }
    }
    

    mock_debugger.pc++;
    server->debugger_state.program_counter = mock_debugger.pc;
    server->debugger_state.source_line++;

    return 0;    
}

static int cmd_step_out(DAPServer *server) {
    // Use the step context that was populated by the protocol handler
    int thread_id = server->current_command.context.step.thread_id;
    // Extract granularity from the context
    StepGranularity granularity = DAP_STEP_GRANULARITY_STATEMENT;
    if (server->current_command.context.step.granularity) {
        if (strcmp(server->current_command.context.step.granularity, "instruction") == 0) {
            granularity = DAP_STEP_GRANULARITY_INSTRUCTION;
        } else if (strcmp(server->current_command.context.step.granularity, "line") == 0) {
            granularity = DAP_STEP_GRANULARITY_LINE;
        }
    }
    
    mock_debugger.pc++;
    server->debugger_state.program_counter = mock_debugger.pc;
    server->debugger_state.source_line++;
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
 * @brief Handler for the launch command
 * 
 * This function handles the launch command in the mock debugger by:
 * 1. Reading launch parameters from the debugger state
 * 2. Setting up the debugger state for the launched program
 * 3. Setting up initial source and debugging state
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
    
    // Clean up old source info
    if (server->current_source) {
        if (server->current_source->path) {
            free((void *)server->current_source->path);
        }
        if (server->current_source->name) {
            free((void *)server->current_source->name);
        }
        free((void *)server->current_source);
        server->current_source = NULL;
    }
    
    // Create and set current source information
    const char* display_source = source_path ? source_path : program_path;
    if (display_source) {
        DAPSource *source = malloc(sizeof(DAPSource));
        if (source) {
            memset(source, 0, sizeof(DAPSource));
            source->path = strdup(display_source);
            if (!source->path) {
                DBG_MOCK_LOG("Error: Failed to allocate memory for source path");
                free(source);
                return -1;
            }
            
            // Extract filename from path
            const char *filename = strrchr(display_source, '/');
            if (filename) {
                source->name = strdup(filename + 1);
            } else {
                source->name = strdup(display_source);
            }
            
            if (!source->name) {
                DBG_MOCK_LOG("Error: Failed to allocate memory for source name");
                free(source->path);
                free(source);
                return -1;
            }
            
            source->presentation_hint = DAP_SOURCE_PRESENTATION_NORMAL;
            source->origin = DAP_SOURCE_ORIGIN_UNKNOWN;
            
            server->current_source = source;
            server->debugger_state.source_line = 1;   // Start at line 1
            server->debugger_state.source_column = 1; // Start at column 1
            
            DBG_MOCK_LOG("Set current source: path=%s, name=%s", 
                      source->path, source->name);
        }
    } else {
        DBG_MOCK_LOG("Warning: No source or program path available for display");
    }
    
    // If map file provided, try to load it
    if (map_path) {
        DBG_MOCK_LOG("Would load map file here: %s", map_path);
        // TODO: Implement map file loading for debugging symbols
    }
    
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
 * @brief Restart command handler
 * 
 * This function handles the restart command by:
 * 1. Resetting debugger state
 * 2. Re-launching the program with the original launch parameters
 * 3. Sending the required events for a restart
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
 */
static int cmd_restart(DAPServer* server) {
    if (!server) {
        return -1;
    }
    
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Restarting debuggee...\n");
    
    // Extract restart parameters
    bool no_debug = server->current_command.context.restart.no_debug;
    
    // Log the restart action
    DBG_MOCK_LOG("Handling restart command (noDebug: %s)", no_debug ? "true" : "false");
    
    // Check if we have the original program path from a previous launch
    const char* program_path = server->debugger_state.program_path;
    if (!program_path) {
        dap_server_send_output_category(server, DAP_OUTPUT_STDERR, "Error: No program to restart\n");
        DBG_MOCK_LOG("Cannot restart - no program_path in debugger state");
        return -1;
    }
    
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Terminating current session...\n");
    
    // Reset debugger state
    mock_debugger.pc = 0;
    mock_debugger.last_event = DAP_EVENT_INVALID;
    
    // Re-initialize program counter and source position
    server->debugger_state.program_counter = 0;
    server->debugger_state.source_line = 1;
    server->debugger_state.source_column = 1;
    server->debugger_state.has_stopped = true;
    
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Relaunching program...\n");
    
    // Send the required events for restart
    // 1. First, terminate existing process
    dap_server_send_event(server, "terminated", NULL);
    
    // 2. Then, notify about the new process
    dap_server_send_process_event(server, program_path, 1, true, "launch");
    
    // 3. Notify about thread start
    dap_server_send_thread_event(server, "started", 1);
    
    // 4. Send stopped event (typically at entry point)
    dap_server_send_stopped_event(server, "entry", "Stopped at program entry after restart");
    
    // Show more detailed information about the restarted program
    char msg[256];
    snprintf(msg, sizeof(msg), "Program restarted: %s\n", program_path);
    dap_server_send_output_category(server, DAP_OUTPUT_IMPORTANT, msg);
    
    // Optionally send a warning for no_debug mode
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
 * 2. Creating a response with available scopes for the frame
 * 3. Sending the response back to the client
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
    
    // Create a response body with scopes
    cJSON *body = cJSON_CreateObject();
    if (!body) {
        DBG_MOCK_LOG("Failed to create response body");
        return -1;
    }
    
    // Add scopes array
    cJSON *scopes = cJSON_CreateArray();
    if (!scopes) {
        cJSON_Delete(body);
        DBG_MOCK_LOG("Failed to create scopes array");
        return -1;
    }
    
    // Add Variables scope (contains local variables)
    cJSON *localsScope = cJSON_CreateObject();
    if (localsScope) {
        cJSON_AddStringToObject(localsScope, "name", "Locals");
        cJSON_AddNumberToObject(localsScope, "variablesReference", 1000);
        cJSON_AddNumberToObject(localsScope, "namedVariables", 5); // Number of local variables
        cJSON_AddBoolToObject(localsScope, "expensive", false);
        cJSON_AddStringToObject(localsScope, "presentationHint", "locals");
        cJSON_AddItemToArray(scopes, localsScope);
    }
    
    // Add CPU Registers scope
    cJSON *registersScope = cJSON_CreateObject();
    if (registersScope) {
        cJSON_AddStringToObject(registersScope, "name", "CPU Registers");
        cJSON_AddNumberToObject(registersScope, "variablesReference", 1001);
        cJSON_AddNumberToObject(registersScope, "namedVariables", 8); // Number of CPU registers
        cJSON_AddBoolToObject(registersScope, "expensive", false);
        cJSON_AddStringToObject(registersScope, "presentationHint", "registers");
        cJSON_AddItemToArray(scopes, registersScope);
    }
    
    // Add Memory scope
    cJSON *memoryScope = cJSON_CreateObject();
    if (memoryScope) {
        cJSON_AddStringToObject(memoryScope, "name", "Memory");
        cJSON_AddNumberToObject(memoryScope, "variablesReference", 1002);
        cJSON_AddNumberToObject(memoryScope, "namedVariables", 3); // Number of memory regions
        cJSON_AddBoolToObject(memoryScope, "expensive", true); // Memory access is expensive
        cJSON_AddItemToArray(scopes, memoryScope);
    }
    
    cJSON_AddItemToObject(body, "scopes", scopes);
    
    // Format the response
    char *response_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    
    if (!response_str) {
        DBG_MOCK_LOG("Failed to format response body");
        return -1;
    }
    
    // Create the response object
    DAPResponse response = {0};
    response.success = true;
    response.data = response_str;
    
    // Send the response
    int seq = server->current_command.request_seq;
    int result = dap_server_send_response(server, DAP_CMD_SCOPES, server->sequence++, seq, true, cJSON_Parse(response.data));
    
    free(response.data);
    
    return (result == 0) ? 0 : -1;
}

/**
 * @brief Variables command handler
 * 
 * This function handles the variables command by:
 * 1. Retrieving the variables_reference from the command context
 * 2. Creating a response with available variables for the reference
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
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Retrieving variables...\n");
    
    // Extract variables_reference from the command context
    int variables_reference = server->current_command.context.variables.variables_reference;
    int filter = server->current_command.context.variables.filter;
    int start = server->current_command.context.variables.start;
    int count = server->current_command.context.variables.count;
    
    DBG_MOCK_LOG("Variables reference: %d, filter: %d, start: %d, count: %d", 
               variables_reference, filter, start, count);
    
    // Create a response body with variables
    cJSON *body = cJSON_CreateObject();
    if (!body) {
        DBG_MOCK_LOG("Failed to create response body");
        return -1;
    }
    
    // Add variables array
    cJSON *variables = cJSON_CreateArray();
    if (!variables) {
        cJSON_Delete(body);
        DBG_MOCK_LOG("Failed to create variables array");
        return -1;
    }
    
    // Handle different variable references
    switch (variables_reference) {
        case 1000: // Locals scope
            // Add some mock local variables
            {
                cJSON *var1 = cJSON_CreateObject();
                if (var1) {
                    cJSON_AddStringToObject(var1, "name", "counter");
                    cJSON_AddStringToObject(var1, "value", "42");
                    cJSON_AddStringToObject(var1, "type", "integer");
                    cJSON_AddNumberToObject(var1, "variablesReference", 0);
                    cJSON_AddItemToArray(variables, var1);
                }
                
                cJSON *var2 = cJSON_CreateObject();
                if (var2) {
                    cJSON_AddStringToObject(var2, "name", "running");
                    cJSON_AddStringToObject(var2, "value", "true");
                    cJSON_AddStringToObject(var2, "type", "boolean");
                    cJSON_AddNumberToObject(var2, "variablesReference", 0);
                    cJSON_AddItemToArray(variables, var2);
                }
                
                cJSON *var3 = cJSON_CreateObject();
                if (var3) {
                    cJSON_AddStringToObject(var3, "name", "message");
                    cJSON_AddStringToObject(var3, "value", "\"Hello World\"");
                    cJSON_AddStringToObject(var3, "type", "string");
                    cJSON_AddNumberToObject(var3, "variablesReference", 0);
                    cJSON_AddItemToArray(variables, var3);
                }
            }
            break;
            
        case 1001: // CPU Registers
            // Add CPU registers as variables
            {
                const char* regs[] = {"A", "B", "X", "P", "S", "D", "L", "T"};
                const char* types[] = {"accumulator", "base", "index", "program counter", "status", "data", "link", "temporary"};
                
                for (int i = 0; i < 8; i++) {
                    cJSON *var = cJSON_CreateObject();
                    if (var) {
                        cJSON_AddStringToObject(var, "name", regs[i]);
                        char value[16];
                        snprintf(value, sizeof(value), "0x%04X", 0x1000 + i * 0x100); // Mock values
                        cJSON_AddStringToObject(var, "value", value);
                        cJSON_AddStringToObject(var, "type", types[i]);
                        cJSON_AddNumberToObject(var, "variablesReference", 0);
                        cJSON_AddStringToObject(var, "presentationHint", "register");
                        cJSON_AddItemToArray(variables, var);
                    }
                }
            }
            break;
            
        case 1002: // Memory regions
            // Add memory region variables
            {
                cJSON *var1 = cJSON_CreateObject();
                if (var1) {
                    cJSON_AddStringToObject(var1, "name", "Stack");
                    cJSON_AddStringToObject(var1, "value", "0x0000-0x1FFF");
                    cJSON_AddStringToObject(var1, "type", "memory");
                    cJSON_AddNumberToObject(var1, "variablesReference", 2000);
                    cJSON_AddItemToArray(variables, var1);
                }
                
                cJSON *var2 = cJSON_CreateObject();
                if (var2) {
                    cJSON_AddStringToObject(var2, "name", "Heap");
                    cJSON_AddStringToObject(var2, "value", "0x2000-0x4FFF");
                    cJSON_AddStringToObject(var2, "type", "memory");
                    cJSON_AddNumberToObject(var2, "variablesReference", 2001);
                    cJSON_AddItemToArray(variables, var2);
                }
                
                cJSON *var3 = cJSON_CreateObject();
                if (var3) {
                    cJSON_AddStringToObject(var3, "name", "Code");
                    cJSON_AddStringToObject(var3, "value", "0x5000-0xFFFF");
                    cJSON_AddStringToObject(var3, "type", "memory");
                    cJSON_AddNumberToObject(var3, "variablesReference", 2002);
                    cJSON_AddItemToArray(variables, var3);
                }
            }
            break;
            
        default:
            // Unknown reference - return empty array
            DBG_MOCK_LOG("Unknown variables reference: %d", variables_reference);
            break;
    }
    
    cJSON_AddItemToObject(body, "variables", variables);
    
    // Format the response
    char *response_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    
    if (!response_str) {
        DBG_MOCK_LOG("Failed to format response body");
        return -1;
    }
    
    // Create the response object
    DAPResponse response = {0};
    response.success = true;
    response.data = response_str;
    
    // Send the response
    int seq = server->current_command.request_seq;
    int result = dap_server_send_response(server, DAP_CMD_VARIABLES, server->sequence++, seq, true, cJSON_Parse(response.data));
    
    free(response.data);
    
    return (result == 0) ? 0 : -1;
}

/*** INITIALIZATION ***/

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
 * @brief Set up callbacks and capabilities for the server
 * 
 * @param server The DAP server instance
 * @return int 0 on success, non-zero on failure
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
    dap_server_register_command_callback(server, DAP_CMD_SCOPES, cmd_scopes);
    dap_server_register_command_callback(server, DAP_CMD_VARIABLES, cmd_variables);
    dap_server_register_command_callback(server, DAP_CMD_EXCEPTION_INFO, on_set_exception_breakpoints);
    dap_server_register_command_callback(server, DAP_CMD_SET_BREAKPOINTS, cmd_set_breakpoints);
    dap_server_register_command_callback(server, DAP_CMD_LAUNCH, cmd_launch);
    dap_server_register_command_callback(server, DAP_CMD_RESTART, cmd_restart);

    // Initialize debugger state
    init_debugger_state(server);

    return 0;
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

/**
 * @brief Simulates a thrown exception and sends an exception stopped event if needed
 * 
 * @param exception_id The ID of the exception (e.g., "NullPointerException")
 * @param description Exception description
 * @param is_uncaught Whether the exception is uncaught
 * @return int 0 if successful, non-zero otherwise
 */
int dbg_mock_throw_exception(const char* exception_id, const char* description, bool is_uncaught) {
    if (!mock_debugger.server) {
        return -1;
    }
    
    DBG_MOCK_LOG("Exception thrown: %s (uncaught: %d)", exception_id, is_uncaught);
    
    // Check if this exception should cause a break
    bool should_break = false;
    
    // Call our should_break check function directly since we no longer have exception_check_callback in DAPServer
    should_break = on_should_break_on_exception(
        mock_debugger.server,
        exception_id,
        is_uncaught,
        &mock_debugger
    );
    
    if (!should_break) {
        DBG_MOCK_LOG("No matching exception filter, continuing execution");
        return 0;
    }
    
    // Create stopped event due to exception
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        return -1;
    }
    
    // We need a thread ID - in our mock server we typically use 1
    int thread_id = 1;
    cJSON_AddNumberToObject(body, "threadId", thread_id);
    
    // Set reason as "exception"
    cJSON_AddStringToObject(body, "reason", "exception");
    
    // Add exception information
    cJSON_AddBoolToObject(body, "allThreadsStopped", true);
    cJSON_AddStringToObject(body, "description", description);
    
    // Add exception text
    cJSON* text = cJSON_CreateObject();
    if (text) {
        if (is_uncaught) {
            cJSON_AddStringToObject(text, "format", "Uncaught exception: {0}");
        } else {
            cJSON_AddStringToObject(text, "format", "Exception: {0}");
        }
        
        cJSON* args = cJSON_CreateArray();
        if (args) {
            cJSON_AddItemToArray(args, cJSON_CreateString(exception_id));
            cJSON_AddItemToObject(text, "variables", args);
        }
        
        cJSON_AddItemToObject(body, "text", text);
    }
    
    // Create the exception info
    cJSON* ex_info = cJSON_CreateObject();
    if (ex_info) {
        cJSON_AddStringToObject(ex_info, "exceptionId", exception_id);
        cJSON_AddStringToObject(ex_info, "description", description);
        cJSON_AddStringToObject(ex_info, "breakMode", is_uncaught ? "unhandled" : "always");
        
        cJSON_AddItemToObject(body, "exceptionInfo", ex_info);
    }
    
    // Send the stopped event using server's built-in function
    int result = dap_server_send_event(mock_debugger.server, "stopped", body);
    if (result != 0) {
        cJSON_Delete(body);
        return -1;
    }
    
    // Update state
    mock_debugger.server->debugger_state.has_stopped = true;
    mock_debugger.last_event = DAP_EVENT_STOPPED;
    
    DBG_MOCK_LOG("Sent exception stopped event");
    return 0;
}

/**
 * @brief Test function to simulate an exception for testing
 * 
 * @param is_uncaught Whether to simulate an uncaught exception (true) or a caught one (false)
 * @return int 0 on success, non-zero on failure
 */
int dbg_mock_test_exception(bool is_uncaught) {
    const char* exception_id = "TestException";
    const char* description = is_uncaught 
        ? "This is a test uncaught exception" 
        : "This is a test caught exception";
    
    DBG_MOCK_LOG("Simulating %s exception", is_uncaught ? "uncaught" : "caught");
    return dbg_mock_throw_exception(exception_id, description, is_uncaught);
}

/**
 * @brief Send a test stopped event to simulate stopping at a specific line
 * 
 * @param line Line number to stop at
 * @param file File path (or NULL to use current)
 * @return int 0 if successful, non-zero otherwise 
 */
int dbg_mock_test_stop_at_line(int line, const char* file) {
    if (!mock_debugger.server) {
        return -1;
    }
    
    DBG_MOCK_LOG("Simulating stop at line %d", line);
    
    // Create stopped event
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        return -1;
    }
    
    // We need a thread ID - in our mock server we typically use 1
    int thread_id = 1;
    cJSON_AddNumberToObject(body, "threadId", thread_id);
    
    // Set reason as "step" (could also be "breakpoint", "pause", etc.)
    cJSON_AddStringToObject(body, "reason", "step");
    cJSON_AddBoolToObject(body, "allThreadsStopped", true);
    
    // Add source information
    if (file) {
        cJSON* source = cJSON_CreateObject();
        if (source) {
            cJSON_AddStringToObject(source, "path", file);
            cJSON_AddStringToObject(source, "name", strrchr(file, '/') ? strrchr(file, '/') + 1 : file);
            cJSON_AddItemToObject(body, "source", source);
        }
        
        // Add line/column info
        cJSON_AddNumberToObject(body, "line", line);
        cJSON_AddNumberToObject(body, "column", 1);  // Default to column 1
    }
    
    // Send the event
    int result = dap_server_send_event(mock_debugger.server, "stopped", body);
    if (result != 0) {
        cJSON_Delete(body);
    }
    
    return result;
}

/**
 * @brief Set up the default capabilities for the mock server
 * 
 * This function configures which DAP capabilities our mock server
 * actually supports based on our implementation.
 * 
 * @param server The DAP server instance
 * @return int The number of capabilities set
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
 * @brief Send demo output messages showing all output categories
 * 
 * This function demonstrates all available output categories by sending
 * example messages for each one.
 * 
 * @param server The DAP server instance
 */
void dbg_mock_send_demo_outputs(DAPServer *server)
{
    if (!server) {
        return;
    }
    
    DBG_MOCK_LOG("Sending demo output messages for all categories");
    
    // Send examples of all output categories
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "This is a normal console message.\n");
    dap_server_send_output_category(server, DAP_OUTPUT_STDOUT, "This is a stdout message (usually blue).\n");
    dap_server_send_output_category(server, DAP_OUTPUT_STDERR, "This is a stderr message (usually red).\n");
    dap_server_send_output_category(server, DAP_OUTPUT_TELEMETRY, "This is a telemetry message (might not be shown).\n");
    dap_server_send_output_category(server, DAP_OUTPUT_IMPORTANT, "This is an important message (highlighted).\n");
    dap_server_send_output_category(server, DAP_OUTPUT_PROGRESS, "This is a progress message (might show with indicator).\n");
    dap_server_send_output_category(server, DAP_OUTPUT_LOG, "This is a log message (usually subdued).\n");
    
    // Also show string-based API for comparison
    dap_server_send_output_event(server, "console", "Using the string API directly: console category\n");
    
    // Simple output (defaults to console)
    dap_server_send_output(server, "Using the simple output API (defaults to console)\n");
}

/**
 * @brief Send launch-related output messages
 * 
 * This function sends output messages after a program is launched,
 * demonstrating the different output categories.
 * 
 * @param server The DAP server instance
 * @param program_path The path to the launched program
 */
void dbg_mock_show_launch_messages(DAPServer *server, const char *program_path)
{
    if (!server) {
        return;
    }
    
    // Safely handle NULL program path
    const char *path_display = program_path ? program_path : "(unknown)";
    
    // Get the complete launch context for more detailed information
    char output_message[512];
    snprintf(output_message, sizeof(output_message), "Program launched: %s\n", path_display);
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, output_message);
    
    // Get additional launch information from the server's debugger state
    const char *source_path = server->debugger_state.source_path;
    const char *map_path = server->debugger_state.map_path;
    
    if (source_path) {
        snprintf(output_message, sizeof(output_message), "Source file: %s\n", source_path);
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, output_message);
    }
    
    if (map_path) {
        snprintf(output_message, sizeof(output_message), "Map file: %s\n", map_path);
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, output_message);
    }
    
    // Show command line args if available
    if (server->debugger_state.args_count > 0 && server->debugger_state.args) {
        
        // Construct a command line display
        char cmdline[256] = "Command line:";
        size_t pos = strlen(cmdline);
        
        for (int i = 0; i < server->debugger_state.args_count && 
             i < 5 && // Limit display to 5 args to prevent buffer overflow
             pos < sizeof(cmdline) - 30; i++) { // Reserve space for ellipsis
            
            const char *arg = server->debugger_state.args[i];
            if (arg) {
                snprintf(cmdline + pos, sizeof(cmdline) - pos, " %s", arg);
                pos = strlen(cmdline);
            }
        }
        
        // If there are more args than we displayed, add ellipsis
        if (server->debugger_state.args_count > 5) {
            snprintf(cmdline + pos, sizeof(cmdline) - pos, " ...");
        }
        
        strcat(cmdline, "\n");
        dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, cmdline);
    }
    
    // Show a warning/stderr example
    dap_server_send_output_category(server, DAP_OUTPUT_STDERR, "Warning: This is a mock debugger!\n");
}

/**
 * @brief Check if a breakpoint is hit at the specified location
 * 
 * @param address Memory address
 * @param source_path Source file path (optional)
 * @param line Line number
 * @return int Breakpoint ID if hit, 0 if no breakpoint
 */
int dbg_mock_is_breakpoint_hit(uint32_t address, const char* source_path, int line) {
    // For now we'll just check based on line number and source path
    // In a real implementation, you'd map addresses to source lines
    
    if (line <= 0) {
        return 0; // Invalid line
    }
    
    for (int i = 0; i < mock_debugger.breakpoint_count; i++) {
        // If source path is specified, match it
        if (source_path && mock_debugger.breakpoints[i].source_path) {
            if (strcmp(source_path, mock_debugger.breakpoints[i].source_path) != 0) {
                continue; // Different source file
            }
        }
        
        // Check line
        if (mock_debugger.breakpoints[i].line == line) {
            DBG_MOCK_LOG("Hit breakpoint %d at line %d in %s", 
                       mock_debugger.breakpoints[i].id,
                       mock_debugger.breakpoints[i].line,
                       mock_debugger.breakpoints[i].source_path ? 
                           mock_debugger.breakpoints[i].source_path : "unknown");
            
            return mock_debugger.breakpoints[i].id;
        }
    }
    
    return 0; // No breakpoint hit
}

/**
 * @brief Trigger a breakpoint hit event
 * 
 * @param breakpoint_id ID of the breakpoint hit
 * @return int 0 on success, non-zero on failure
 */
int dbg_mock_trigger_breakpoint_hit(int breakpoint_id) {
    if (!mock_debugger.server || breakpoint_id <= 0) {
        return -1;
    }



    // Find the breakpoint
    MockBreakpoint* bp = NULL;
    for (int i = 0; i < mock_debugger.breakpoint_count; i++) {
        if (mock_debugger.breakpoints[i].id == breakpoint_id) {
            bp = &mock_debugger.breakpoints[i];
            break;
        }
    }
    
    if (!bp) {
        DBG_MOCK_LOG("Breakpoint %d not found", breakpoint_id);
        return -1;
    }
    
    


   
    // Add description
    char description[128];
    snprintf(description, sizeof(description), "Breakpoint %d hit at line %d", breakpoint_id, bp->line);
        

#if 0 // later maybe fill this    
    // Add hitBreakpointIds array
    cJSON* hit_ids = cJSON_CreateArray();
    if (hit_ids) {
        cJSON_AddItemToArray(hit_ids, cJSON_CreateNumber(breakpoint_id));
        cJSON_AddItemToObject(body, "hitBreakpointIds", hit_ids);
    }
#endif

    // Send the stopped event
    // Stopped because a breakpoint was hit.
    dap_server_send_stopped_event(mock_debugger.server, "breakpoint", description); 
    
    
    // Update state
    mock_debugger.server->debugger_state.has_stopped = true;
    mock_debugger.last_event = DAP_EVENT_STOPPED;
    
    DBG_MOCK_LOG("Sent breakpoint stopped event");
    return 0;
}


