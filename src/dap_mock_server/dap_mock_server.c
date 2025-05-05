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
static int on_set_exception_breakpoints(DAPServer *server);
static bool on_should_break_on_exception(DAPServer *server, const char* exception_id, bool is_uncaught, void* user_data);
static int clear_breakpoints_for_source(const char* source_path);
static int cmd_set_breakpoints(DAPServer* server);

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

/*** INITIALIZATION ***/

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

    // Set up stepping callbacks through command callbacks only
    // Register command-specific implementations using the wrapper functions
    dap_server_register_command_callback(mock_debugger.server, DAP_CMD_NEXT, cmd_next);
    dap_server_register_command_callback(mock_debugger.server, DAP_CMD_STEP_IN, cmd_step_in);
    dap_server_register_command_callback(mock_debugger.server, DAP_CMD_STEP_OUT, cmd_step_out);
    
    // Register exception breakpoint callback
    dap_server_register_command_callback(mock_debugger.server, DAP_CMD_SET_EXCEPTION_BREAKPOINTS, on_set_exception_breakpoints);
    
    // Register breakpoint callback
    dap_server_register_command_callback(mock_debugger.server, DAP_CMD_SET_BREAKPOINTS, cmd_set_breakpoints);
    
    // Configure which capabilities are supported
    dbg_mock_set_default_capabilities(mock_debugger.server);

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
        
        // End of capabilities
        DAP_CAP_COUNT
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
    if (!server || !program_path) {
        return;
    }
    
    // Send some output messages to demonstrate different categories
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Program launched: ");
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, program_path);

    
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


