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
#include <cjson/cJSON.h>
#include "../libdap/include/dap_server.h"
#include "../libdap/include/dap_error.h"
#include "../libdap/include/dap_types.h"
#include "../libdap/include/dap_transport.h"
#include "../libdap/include/dap_protocol.h"
#include "../libdap/include/dap_debugger.h"

#include "dap_mock_server.h"

#define DAP_EVENT_STOPPED DAP_EVENT_STOPPED
#define DAP_EVENT_CONTINUED DAP_EVENT_OUTPUT
#define DAP_EVENT_EXITED DAP_EVENT_EXITED
#define DAP_EVENT_TERMINATED DAP_EVENT_TERMINATED
#define DAP_EVENT_NONE DAP_EVENT_INVALID
#define MAX_BREAKPOINTS 32

// Register structure and list
typedef struct {
    const char* name;
    uint16_t value;
    const char* type;
    bool has_nested;  // Whether this register has nested variables (like status flags)
    int nested_ref;   // Reference number for nested variables
} Register;

// Status flag structure
typedef struct {
    const char* name;
    bool value;
    const char* type;
} StatusFlag;

// Define status flags for the status register
static StatusFlag status_flags[] = {
    { "PTM",  false, "flag" },  // Page Table Flag
    { "TG",   false, "flag" },  // Floating point rounding flag
    { "K",    false, "flag" },  // Accumulator
    { "Z",    false, "flag" },  // Error flag
    { "Q",    false, "flag" },  // Dynamic overflow flag
    { "O",    false, "flag" },  // Static overflow flag
    { "C",    false, "flag" },  // Carry flag
    { "M",    false, "flag" },  // Multi-shift link flag
    { "PIL",  0,     "level" }, // Program Level (4 bits)
    { "N100", true,  "flag" },  // ND-100 flag (always 1)
    { "SEXI", false, "flag" },  // Memory management extended mode
    { "PONI", false, "flag" },  // Memory management ON flag
    { "IONI", false, "flag" }   // Interrupt system ON flag
};

#define NUM_STATUS_FLAGS (sizeof(status_flags) / sizeof(StatusFlag))

// Define CPU registers for ND-100
static Register cpu_registers[] = {
    { "STS", 0x0000, "bitmask", true, 1001 },  // Status register with nested flags
    { "D",   0x0000, "integer", false, 0 },    // Data register
    { "P",   0x1000, "integer", false, 0 },    // Program counter
    { "B",   0x0000, "integer", false, 0 },    // Base register
    { "L",   0x0000, "integer", false, 0 },    // Link register
    { "A",   0x0000, "integer", false, 0 },    // Accumulator
    { "T",   0x0000, "integer", false, 0 },    // Temporary register
    { "X",   0x0000, "integer", false, 0 }     // Index register
};

#define NUM_REGISTERS (sizeof(cpu_registers) / sizeof(Register))

// Define internal registers for read
static Register internal_read_registers[] = {
    { "PANC", 0x0000, "octal", false, 0 },  // Panel control
    { "STS",  0x0001, "octal", false, 0 },  // Status register
    { "LMP",  0x0002, "octal", false, 0 },  // Panel data display buffer register
    { "PCR",  0x0003, "octal", false, 0 },  // Paging control register
    { "IIE",  0x0005, "octal", false, 0 },  // Internal interrupt enable register
    { "PID",  0x0006, "octal", false, 0 },  // Priority interrupt detect register
    { "PIE",  0x0007, "octal", false, 0 },  // Priority interrupt enable register
    { "CCL",  0x0010, "octal", false, 0 },  // Cache clear register
    { "LCIL", 0x0011, "octal", false, 0 },  // Lower cache inhibit limit register
    { "UCIL", 0x0012, "octal", false, 0 },  // Upper cache inhibit limit register
    { "CILP", 0x0013, "octal", false, 0 },  // Cache inhibit page register
    { "ECCR", 0x0015, "octal", false, 0 },  // Error correction control register
    { "CS",   0x0017, "octal", false, 0 }   // Control Store
};

#define NUM_INTERNAL_READ_REGISTERS (sizeof(internal_read_registers) / sizeof(Register))

// Define internal registers for write
static Register internal_write_registers[] = {
    { "PANS", 0x0000, "octal", false, 0 },  // Panel status
    { "STS",  0x0001, "octal", false, 0 },  // Status register
    { "OPR",  0x0002, "octal", false, 0 },  // Operator's panel switch register
    { "PSR",  0x0003, "octal", false, 0 },  // Paging status register
    { "PVL",  0x0004, "octal", false, 0 },  // Previous level code register
    { "IIC",  0x0005, "octal", false, 0 },  // Internal interrupt code register
    { "PID",  0x0006, "octal", false, 0 },  // Priority interrupt detect register
    { "PIE",  0x0007, "octal", false, 0 },  // Priority enable detect register
    { "CSR",  0x0010, "octal", false, 0 },  // Cache status register
    { "ACTL", 0x0011, "octal", false, 0 },  // Active level register
    { "ALD",  0x0012, "octal", false, 0 },  // Automatic load descriptor
    { "PES",  0x0013, "octal", false, 0 },  // Parity error status register
    { "PGC",  0x0014, "octal", false, 0 },  // Paging control register
    { "PEA",  0x0015, "octal", false, 0 },  // Parity error address register
    { "CS",   0x0017, "octal", false, 0 }   // Control store
};

#define NUM_INTERNAL_WRITE_REGISTERS (sizeof(internal_write_registers) / sizeof(Register))

// Forward declarations
struct DAPServer;
static void cleanup_line_maps(MockDebugger* debugger);
static void cleanup_breakpoints(MockDebugger* debugger);

// Add function declaration at the top with other declarations
static int handle_initialize(DAPResponse* response);
static int handle_launch(DAPResponse* response, cJSON* arguments);
static int handle_attach(cJSON* args, DAPResponse* response);
static int handle_disconnect(DAPResponse* response);
static int handle_terminate(DAPResponse* response);
static int handle_restart(DAPResponse* response);
static int handle_execution_control(DAPCommandType command, cJSON* args, DAPResponse* response);
static int handle_set_breakpoints(cJSON* args, DAPResponse* response);
static int handle_source(cJSON* args, DAPResponse* response);
static int handle_threads(DAPResponse* response);
static int handle_stack_trace(cJSON* args, DAPResponse* response);
static int handle_scopes(cJSON* args, DAPResponse* response);
static int handle_variables(cJSON* args, DAPResponse* response);
static int handle_continue(cJSON* args, DAPResponse* response);
static int handle_next(cJSON* args, DAPResponse* response);
static int handle_step_in(cJSON* args, DAPResponse* response);
static int handle_step_out(cJSON* args, DAPResponse* response);
static int handle_configuration_done(DAPResponse* response);
static int handle_read_memory(cJSON* args, DAPResponse* response);
static int handle_write_memory(cJSON* args, DAPResponse* response);
static int handle_read_registers(cJSON* args, DAPResponse* response);
static int handle_write_register(cJSON* args, DAPResponse* response);
static int mock_handle_command(void* user_data, DAPCommandType command, const char* args, DAPResponse* response);

// Helper functions for response handling
static void set_response_error(DAPResponse* response, const char* error_message) {
    if (response) {
        response->success = false;
        response->error_message = strdup(error_message);
        response->data = NULL;
        response->data_size = 0;
    }
}

static void set_response_success(DAPResponse* response, cJSON* body) {
    if (response) {
        response->success = true;
        response->error_message = NULL;
        if (body) {
            response->data = cJSON_PrintUnformatted(body);
            response->data_size = strlen(response->data);
        } else {
            response->data = NULL;
            response->data_size = 0;
        }
    }
}

// Update the line_maps field in MockDebugger initialization
MockDebugger mock_debugger = {
    .server = NULL,
    .running = false,
    .attached = false,
    .paused = false,
    .program_path = NULL,
    .current_thread = 1,
    .pc = 0,
    .breakpoint_count = 0,
    .breakpoints = NULL,
    .current_source = NULL,
    .current_line = 0,
    .current_column = 0,
    .last_event = DAP_EVENT_NONE,
    .memory_size = 0,
    .memory = NULL,
    .register_count = 0,
    .registers = NULL,
    .line_maps = NULL,
    .line_map_count = 0,
    .line_map_capacity = 0
};

// Event handling callback
static int handle_event(void* user_data, DAPEventType event, const char* content) {
    MockDebugger* debugger = (MockDebugger*)user_data;
    if (!debugger) {
        return -1;
    }

    debugger->last_event = event;
    const char* event_str = get_event_string(event);
    printf("DEBUG: Received event: %s, content: %s\n", event_str ? event_str : "unknown", content ? content : "NULL");
    return 0;
}

// Breakpoint structure
typedef struct {
    char* file_path;
    int line;
    bool verified;
} Breakpoint;

// Update add_breakpoint to use MockDebugger
static void add_breakpoint(const char* file_path, int line) {
    // Check if breakpoint already exists
    for (int i = 0; i < mock_debugger.breakpoint_count; i++) {
        if (mock_debugger.breakpoints[i].source && 
            strcmp(mock_debugger.breakpoints[i].source->path, file_path) == 0 && 
            mock_debugger.breakpoints[i].line == line) {
            return; // Breakpoint already exists
        }
    }

    // Resize array if needed
    if (mock_debugger.breakpoint_count >= MAX_BREAKPOINTS) {
        return;
    }

    DAPBreakpoint* new_breakpoints = realloc(mock_debugger.breakpoints, 
                                           (mock_debugger.breakpoint_count + 1) * sizeof(DAPBreakpoint));
    if (!new_breakpoints) {
        return;
    }

    mock_debugger.breakpoints = new_breakpoints;
    mock_debugger.breakpoints[mock_debugger.breakpoint_count].line = line;
    mock_debugger.breakpoints[mock_debugger.breakpoint_count].column = 0;
    mock_debugger.breakpoints[mock_debugger.breakpoint_count].verified = true;
    
    // Set the source
    DAPSource* bp_source = malloc(sizeof(DAPSource));
    if (bp_source) {
        bp_source->path = strdup(file_path);
        mock_debugger.breakpoints[mock_debugger.breakpoint_count].source = bp_source;
    }
    
    mock_debugger.breakpoint_count++;
}

// Update remove_breakpoints to use MockDebugger
static void remove_breakpoints(const char* file_path) {
    for (int i = 0; i < mock_debugger.breakpoint_count; i++) {
        if (mock_debugger.breakpoints[i].source && 
            strcmp(mock_debugger.breakpoints[i].source->path, file_path) == 0) {
            // Free the source
            if (mock_debugger.breakpoints[i].source) {
                free(mock_debugger.breakpoints[i].source->path);
                free(mock_debugger.breakpoints[i].source);
            }
            
            // Move last breakpoint to this position
            if (i < mock_debugger.breakpoint_count - 1) {
                mock_debugger.breakpoints[i] = mock_debugger.breakpoints[mock_debugger.breakpoint_count - 1];
            }
            mock_debugger.breakpoint_count--;
            i--; // Check this position again
        }
    }
}

// Update get_breakpoints_for_file to use MockDebugger
static cJSON* get_breakpoints_for_file(const char* file_path) {
    cJSON* breakpoints = cJSON_CreateArray();
    if (!breakpoints) return NULL;

    for (int i = 0; i < mock_debugger.breakpoint_count; i++) {
        if (mock_debugger.breakpoints[i].source && 
            strcmp(mock_debugger.breakpoints[i].source->path, file_path) == 0) {
            cJSON* bp = cJSON_CreateObject();
            if (bp) {
                cJSON_AddNumberToObject(bp, "line", mock_debugger.breakpoints[i].line);
                cJSON_AddBoolToObject(bp, "verified", mock_debugger.breakpoints[i].verified);
                cJSON_AddItemToArray(breakpoints, bp);
            }
        }
    }

    return breakpoints;
}

// Add helper function for line mapping
static int get_line_for_address(uint32_t address) {
    for (int i = 0; i < mock_debugger.line_map_count; i++) {
        if (mock_debugger.line_maps[i].address == address) {
            return mock_debugger.line_maps[i].line;
        }
    }
    return -1;
}

// Fix pointer type in add_line_map
static void add_line_map(const char* file_path, int line, uint32_t address) {
    if (mock_debugger.line_map_count >= mock_debugger.line_map_capacity) {
        size_t new_capacity = mock_debugger.line_map_capacity == 0 ? 16 : mock_debugger.line_map_capacity * 2;
        SourceLineMap* new_maps = realloc(mock_debugger.line_maps, new_capacity * sizeof(SourceLineMap));
        if (!new_maps) {
            return;
        }
        mock_debugger.line_maps = new_maps;
        mock_debugger.line_map_capacity = new_capacity;
    }

    mock_debugger.line_maps[mock_debugger.line_map_count].file_path = strdup(file_path);
    mock_debugger.line_maps[mock_debugger.line_map_count].line = line;
    mock_debugger.line_maps[mock_debugger.line_map_count].address = address;
    mock_debugger.line_map_count++;
}

// Update mock_handle_command to use the declared function
static int mock_handle_command(void* user_data, DAPCommandType command,
                             const char* args, DAPResponse* response) {
    (void)user_data;  // Mark as unused
    if (!response) {
        return -1;
    }

    // Convert args string to cJSON if needed
    cJSON* json_args = args ? cJSON_Parse(args) : NULL;
    if (args && !json_args) {
        response->success = false;
        response->error_message = strdup("Failed to parse arguments");
        return 0;
    }

    // Handle different commands
    int result = 0;
    switch (command) {
        case DAP_CMD_INITIALIZE:
            result = handle_initialize(response);
            break;
        case DAP_CMD_LAUNCH:
            result = handle_launch(response, json_args);
            break;
        case DAP_CMD_ATTACH:
            result = handle_attach(json_args, response);
            break;
        case DAP_CMD_DISCONNECT:
            cleanup_breakpoints(&mock_debugger);
            result = handle_disconnect(response);
            break;
        case DAP_CMD_TERMINATE:
            result = handle_terminate(response);
            break;
        case DAP_CMD_RESTART:
            result = handle_restart(response);
            break;
        case DAP_CMD_SET_BREAKPOINTS:
            result = handle_set_breakpoints(json_args, response);
            break;
        case DAP_CMD_CONFIGURATION_DONE:
            result = handle_configuration_done(response);
            break;
        case DAP_CMD_THREADS:
            result = handle_threads(response);
            break;
        case DAP_CMD_STACK_TRACE:
            result = handle_stack_trace(json_args, response);
            break;
        case DAP_CMD_SCOPES:
            result = handle_scopes(json_args, response);
            break;
        case DAP_CMD_VARIABLES:
            result = handle_variables(json_args, response);
            break;
        case DAP_CMD_CONTINUE:
            result = handle_continue(json_args, response);
            break;
        case DAP_CMD_NEXT:
            result = handle_next(json_args, response);
            break;
        case DAP_CMD_STEP_IN:
            result = handle_step_in(json_args, response);
            break;
        case DAP_CMD_STEP_OUT:
            result = handle_step_out(json_args, response);
            break;
        case DAP_CMD_PAUSE: {
            cJSON* json_args = cJSON_Parse(args);
            if (!json_args) {
                set_response_error(response, "Invalid arguments");
                return 0;
            }
            int result = handle_pause(json_args, response);
            cJSON_Delete(json_args);
            return result;
        }
        case DAP_CMD_READ_MEMORY:
            result = handle_read_memory(json_args, response);
            break;
        case DAP_CMD_WRITE_MEMORY:
            result = handle_write_memory(json_args, response);
            break;
        case DAP_CMD_READ_REGISTERS:
            result = handle_read_registers(json_args, response);
            break;
        case DAP_CMD_WRITE_REGISTERS:
            result = handle_write_register(json_args, response);
            break;
        case DAP_CMD_SOURCE:
            result = handle_source(json_args, response);
            break;
        default:
            response->success = false;
            response->error_message = strdup("Unknown command");
            result = 0;
            break;
    }

    if (json_args) {
        cJSON_Delete(json_args);
    }
    return result;
}

static int handle_initialize(DAPResponse* response) {
    if (!response) {
        return -1;
    }

    cJSON* capabilities = cJSON_CreateObject();
    if (!capabilities) {
        set_response_error(response, "Failed to create capabilities object");
        return -1;
    }

    // Set supported capabilities
    cJSON_AddBoolToObject(capabilities, "supportsConfigurationDoneRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsFunctionBreakpoints", true);
    cJSON_AddBoolToObject(capabilities, "supportsConditionalBreakpoints", true);
    cJSON_AddBoolToObject(capabilities, "supportsHitConditionalBreakpoints", true);
    cJSON_AddBoolToObject(capabilities, "supportsEvaluateForHovers", true);
    cJSON_AddBoolToObject(capabilities, "supportsStepBack", false);
    cJSON_AddBoolToObject(capabilities, "supportsSetVariable", true);
    cJSON_AddBoolToObject(capabilities, "supportsRestartFrame", false);
    cJSON_AddBoolToObject(capabilities, "supportsGotoTargetsRequest", false);
    cJSON_AddBoolToObject(capabilities, "supportsStepInTargetsRequest", false);
    cJSON_AddBoolToObject(capabilities, "supportsCompletionsRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsModulesRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsRestartRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsExceptionOptions", true);
    cJSON_AddBoolToObject(capabilities, "supportsValueFormattingOptions", true);
    cJSON_AddBoolToObject(capabilities, "supportsExceptionInfoRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportTerminateDebuggee", true);
    cJSON_AddBoolToObject(capabilities, "supportsDelayedStackTraceLoading", true);
    cJSON_AddBoolToObject(capabilities, "supportsLoadedSourcesRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsLogPoints", true);
    cJSON_AddBoolToObject(capabilities, "supportsTerminateThreadsRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsSetExpression", true);
    cJSON_AddBoolToObject(capabilities, "supportsTerminateRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsDataBreakpoints", true);
    cJSON_AddBoolToObject(capabilities, "supportsReadMemoryRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsWriteMemoryRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsDisassembleRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsCancelRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsBreakpointLocationsRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsClipboardContext", true);
    cJSON_AddBoolToObject(capabilities, "supportsSteppingGranularity", true);
    cJSON_AddBoolToObject(capabilities, "supportsInstructionBreakpoints", true);
    cJSON_AddBoolToObject(capabilities, "supportsExceptionFilterOptions", true);
    cJSON_AddBoolToObject(capabilities, "supportsSingleThreadExecutionRequests", true);

    set_response_success(response, capabilities);
    cJSON_Delete(capabilities);
    return 0;
}

static int handle_launch(DAPResponse* response, cJSON* arguments) {
    if (!response || !arguments) {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    // Get program path from arguments
    cJSON* program = cJSON_GetObjectItem(arguments, "program");
    if (!program || !cJSON_IsString(program)) {
        set_response_error(response, "Missing or invalid program path");
        return -1;
    }

    // Get stop at entry flag
    cJSON* stopAtEntry = cJSON_GetObjectItem(arguments, "stopAtEntry");
    bool shouldStopAtEntry = stopAtEntry && cJSON_IsTrue(stopAtEntry);

    // Create success response
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    cJSON_AddStringToObject(body, "program", program->valuestring);
    cJSON_AddBoolToObject(body, "stopAtEntry", shouldStopAtEntry);

    set_response_success(response, body);
    cJSON_Delete(body);

    // Set debugger state
    mock_debugger.running = true;
    mock_debugger.attached = true;
    mock_debugger.paused = true;

    // Send stopped event after launch, per DAP spec
    DAPServer* server = (DAPServer*)mock_debugger.server;
    if (server && server->config.callbacks.handle_event) {
        cJSON* event_body = cJSON_CreateObject();
        if (event_body) {
            cJSON_AddStringToObject(event_body, "reason", "entry");
            cJSON_AddNumberToObject(event_body, "threadId", 1);
            cJSON_AddBoolToObject(event_body, "allThreadsStopped", true);

            char* event_body_str = cJSON_PrintUnformatted(event_body);
            if (event_body_str) {
                server->config.callbacks.handle_event(
                    server->config.user_data,
                    DAP_EVENT_STOPPED,
                    event_body_str
                );
                free(event_body_str);
            }
            cJSON_Delete(event_body);
        }
    }
    return 0;
}

static int handle_attach(cJSON* args, DAPResponse* response) {
    cJSON* pid = cJSON_GetObjectItem(args, "pid");
    if (!pid || !cJSON_IsNumber(pid)) {
        response->success = false;
        response->error_message = strdup("Missing or invalid process ID");
        return 0;
    }

    mock_debugger.running = true;
    mock_debugger.attached = true;
    mock_debugger.paused = true;
    
    response->success = true;
    response->data = strdup("{}");
    return 0;
}

static int handle_disconnect(DAPResponse* response) {
    printf("Disconnecting from debuggee\n");
    
    response->success = true;
    response->data = strdup("{}");
    return 0;
}

static int handle_terminate(DAPResponse* response) {
    printf("Terminating debuggee\n");
    
    response->success = true;
    response->data = strdup("{}");
    return 0;
}

static int handle_restart(DAPResponse* response) {
    printf("Restarting debuggee\n");
    
    response->success = true;
    response->data = strdup("{}");
    return 0;
}

/**
 * @brief Handle execution control commands (continue, step, etc.)
 * 
 * This function is currently unused but kept for future execution control implementation.
 * It will be used to centralize the handling of all execution control commands
 * and provide consistent behavior across different execution modes.
 */
static int handle_execution_control(DAPCommandType command, cJSON* args, DAPResponse* response) {
    if (!mock_debugger.running || !mock_debugger.attached) {
        set_response_error(response, "Debugger is not running or not attached");
        return -1;
    }

    // Parse thread ID and single_thread flag
    int thread_id = 1;  // Default to thread 1
    bool single_thread = false;

    if (args) {
        cJSON* thread_id_json = cJSON_GetObjectItem(args, "threadId");
        if (thread_id_json && cJSON_IsNumber(thread_id_json)) {
            thread_id = thread_id_json->valueint;
        }

        cJSON* single_thread_json = cJSON_GetObjectItem(args, "singleThread");
        if (single_thread_json && cJSON_IsBool(single_thread_json)) {
            single_thread = cJSON_IsTrue(single_thread_json);
        }
    }

    // Validate thread ID
    if (thread_id != 1) {
        set_response_error(response, "Invalid thread ID - only thread 1 is supported");
        return -1;
    }

    // Handle different commands
    switch (command) {
        case DAP_CMD_PAUSE:
            if (!mock_debugger.paused) {
                mock_debugger.paused = true;
                // If single_thread is true, only pause the specified thread
                if (single_thread && thread_id != mock_debugger.current_thread) {
                    set_response_error(response, "Cannot pause non-current thread in single-thread mode");
                    return -1;
                }

                // Create success response with thread information
                cJSON* body = cJSON_CreateObject();
                if (!body) {
                    set_response_error(response, "Failed to create response body");
                    return -1;
                }

                cJSON_AddNumberToObject(body, "threadId", thread_id);
                cJSON_AddStringToObject(body, "reason", "pause");
                cJSON_AddBoolToObject(body, "allThreadsStopped", true);

                set_response_success(response, body);
                cJSON_Delete(body);

                // Send stopped event according to DAP spec
                DAPServer* server = (DAPServer*)mock_debugger.server;
                if (server && server->config.callbacks.handle_event) {
                    cJSON* event_body = cJSON_CreateObject();
                    if (event_body) {
                        cJSON_AddNumberToObject(event_body, "threadId", thread_id);
                        cJSON_AddStringToObject(event_body, "reason", "pause");
                        cJSON_AddBoolToObject(event_body, "allThreadsStopped", true);
                        
                        char* event_body_str = cJSON_PrintUnformatted(event_body);
                        if (event_body_str) {
                            server->config.callbacks.handle_event(server->config.user_data,
                                                               DAP_EVENT_STOPPED,
                                                               event_body_str);
                            free(event_body_str);
                        }
                        cJSON_Delete(event_body);
                    }
                }
                return 0;
            }
            set_response_error(response, "Debugger is already paused");
            return -1;
        
        case DAP_CMD_CONTINUE:
        case DAP_CMD_NEXT:
        case DAP_CMD_STEP_IN:
        case DAP_CMD_STEP_OUT:
            if (mock_debugger.paused) {
                // If single_thread is true, only continue the specified thread
                if (single_thread && thread_id != mock_debugger.current_thread) {
                    set_response_error(response, "Cannot continue non-current thread in single-thread mode");
                    return -1;
                }
                mock_debugger.paused = false;
                set_response_success(response, NULL);
                return 0;
            }
            set_response_error(response, "Debugger is not paused");
            return -1;

        default:
            set_response_error(response, "Unsupported execution control command");
            return -1;
    }
}

static int handle_set_breakpoints(cJSON* args, DAPResponse* response) {
    if (!args || !response) {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    // Get source file path
    cJSON* source = cJSON_GetObjectItem(args, "source");
    if (!source) {
        set_response_error(response, "Missing source");
        return -1;
    }

    cJSON* path = cJSON_GetObjectItem(source, "path");
    if (!path || !cJSON_IsString(path)) {
        set_response_error(response, "Invalid source path");
        return -1;
    }

    const char* file_path = path->valuestring;
    if (!file_path) {
        set_response_error(response, "Invalid file path");
        return -1;
    }

    // Get breakpoints array
    cJSON* breakpoints = cJSON_GetObjectItem(args, "breakpoints");
    if (!breakpoints || !cJSON_IsArray(breakpoints)) {
        set_response_error(response, "Missing or invalid breakpoints array");
        return -1;
    }

    // Remove existing breakpoints for this file (DAP spec requirement)
    remove_breakpoints(file_path);

    // Add new breakpoints (if any)
    int array_size = cJSON_GetArraySize(breakpoints);
    for (int i = 0; i < array_size; i++) {
        cJSON* bp = cJSON_GetArrayItem(breakpoints, i);
        if (bp) {
            cJSON* line = cJSON_GetObjectItem(bp, "line");
            if (line && cJSON_IsNumber(line)) {
                add_breakpoint(file_path, line->valueint);
            }
        }
    }

    // Create response with current breakpoints (DAP spec requirement)
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    cJSON* response_breakpoints = get_breakpoints_for_file(file_path);
    if (response_breakpoints) {
        cJSON_AddItemToObject(body, "breakpoints", response_breakpoints);
    }

    // Set success response
    response->success = true;
    response->data = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    return 0;
}

static int handle_source(cJSON* args, DAPResponse* response) {
    if (!args || !response) {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    cJSON* source = cJSON_GetObjectItem(args, "source");
    if (!source) {
        set_response_error(response, "No source specified");
        return -1;
    }

    cJSON* path = cJSON_GetObjectItem(source, "path");
    if (!path || !cJSON_IsString(path)) {
        set_response_error(response, "Invalid source path");
        return -1;
    }

    // Create response body with source content
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Add source content to response
    cJSON_AddStringToObject(body, "content", "Source content here");
    cJSON_AddStringToObject(body, "mimeType", "text/plain");

    set_response_success(response, body);
    return 0;
}

static int handle_scopes(cJSON* args, DAPResponse* response) {
    if (!args || !response) {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    cJSON* frameId = cJSON_GetObjectItem(args, "frameId");
    if (!frameId || !cJSON_IsNumber(frameId)) {
        set_response_error(response, "Invalid frame ID");
        return -1;
    }

    // Create response body with scopes
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Add scopes array
    cJSON* scopes = cJSON_CreateArray();
    if (!scopes) {
        cJSON_Delete(body);
        set_response_error(response, "Failed to create scopes array");
        return -1;
    }

    // Add CPU Registers scope (always available, even at entry point)
    cJSON* registersScope = cJSON_CreateObject();
    if (registersScope) {
        cJSON_AddStringToObject(registersScope, "name", "CPU Registers");
        cJSON_AddNumberToObject(registersScope, "variablesReference", 1);
        cJSON_AddNumberToObject(registersScope, "namedVariables", 8);  // Number of CPU registers
        cJSON_AddBoolToObject(registersScope, "expensive", false);
        cJSON_AddStringToObject(registersScope, "presentationHint", "registers");
        cJSON_AddItemToArray(scopes, registersScope);
    }

    // Add CPU Flags scope (always available, even at entry point)
    cJSON* flagsScope = cJSON_CreateObject();
    if (flagsScope) {
        cJSON_AddStringToObject(flagsScope, "name", "CPU Flags");
        cJSON_AddNumberToObject(flagsScope, "variablesReference", 1001);
        cJSON_AddNumberToObject(flagsScope, "namedVariables", 4);  // Number of CPU flags
        cJSON_AddBoolToObject(flagsScope, "expensive", false);
        cJSON_AddStringToObject(flagsScope, "presentationHint", "registers");
        cJSON_AddItemToArray(scopes, flagsScope);
    }

    // Add Internal Registers scope (always available, even at entry point)
    cJSON* internalScope = cJSON_CreateObject();
    if (internalScope) {
        cJSON_AddStringToObject(internalScope, "name", "Internal Registers");
        cJSON_AddNumberToObject(internalScope, "variablesReference", 4);
        cJSON_AddNumberToObject(internalScope, "namedVariables", 2);  // Number of internal registers
        cJSON_AddBoolToObject(internalScope, "expensive", false);
        cJSON_AddStringToObject(internalScope, "presentationHint", "registers");
        cJSON_AddItemToArray(scopes, internalScope);
    }

    cJSON_AddItemToObject(body, "scopes", scopes);
    set_response_success(response, body);
    return 0;
}

static int handle_variables(cJSON* args, DAPResponse* response) {
    if (!args || !response) {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    cJSON* variablesReference = cJSON_GetObjectItem(args, "variablesReference");
    if (!variablesReference || !cJSON_IsNumber(variablesReference)) {
        set_response_error(response, "Invalid variables reference");
        return -1;
    }

    // Create response body with variables
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Add variables array
    cJSON* variables = cJSON_CreateArray();
    if (!variables) {
        cJSON_Delete(body);
        set_response_error(response, "Failed to create variables array");
        return -1;
    }

    int ref = variablesReference->valueint;
    Register* reg_array = NULL;
    size_t reg_count = 0;
    cJSON* readScope = NULL;
    cJSON* writeScope = NULL;

    // Select appropriate register array based on reference
    switch (ref) {
        case 1:  // CPU Registers
            reg_array = cpu_registers;
            reg_count = NUM_REGISTERS;
            break;
        case 2:  // Internal Read Registers
            reg_array = internal_read_registers;
            reg_count = NUM_INTERNAL_READ_REGISTERS;
            break;
        case 3:  // Internal Write Registers
            reg_array = internal_write_registers;
            reg_count = NUM_INTERNAL_WRITE_REGISTERS;
            break;
        case 4:  // Internal Registers parent scope
            // Add subscopes for internal registers with detailed information
            readScope = cJSON_CreateObject();
            if (readScope) {
                cJSON_AddStringToObject(readScope, "name", "Read Registers");
                cJSON_AddStringToObject(readScope, "value", "Read-only internal registers");
                cJSON_AddStringToObject(readScope, "type", "scope");
                cJSON_AddNumberToObject(readScope, "variablesReference", 2);
                cJSON_AddNumberToObject(readScope, "namedVariables", NUM_INTERNAL_READ_REGISTERS);
                cJSON_AddBoolToObject(readScope, "expensive", false);
                cJSON_AddStringToObject(readScope, "presentationHint", "registers");
                cJSON_AddItemToArray(variables, readScope);
            }
            writeScope = cJSON_CreateObject();
            if (writeScope) {
                cJSON_AddStringToObject(writeScope, "name", "Write Registers");
                cJSON_AddStringToObject(writeScope, "value", "Write-only internal registers");
                cJSON_AddStringToObject(writeScope, "type", "scope");
                cJSON_AddNumberToObject(writeScope, "variablesReference", 3);
                cJSON_AddNumberToObject(writeScope, "namedVariables", NUM_INTERNAL_WRITE_REGISTERS);
                cJSON_AddBoolToObject(writeScope, "expensive", false);
                cJSON_AddStringToObject(writeScope, "presentationHint", "registers");
                cJSON_AddItemToArray(variables, writeScope);
            }
            break;
        case 1001:  // Status Register Flags
            // Add status flags as variables
            for (size_t i = 0; i < NUM_STATUS_FLAGS; i++) {
                cJSON* var = cJSON_CreateObject();
                if (var) {
                    cJSON_AddStringToObject(var, "name", status_flags[i].name);
                    cJSON_AddStringToObject(var, "value", status_flags[i].value ? "1" : "0");
                    cJSON_AddStringToObject(var, "type", status_flags[i].type);
                    cJSON_AddNumberToObject(var, "variablesReference", 0);
                    cJSON_AddItemToArray(variables, var);
                }
            }
            break;
        default: {
            // Create error response
            response->success = false;
            
            // Create error object with more user-friendly message
            cJSON* error = cJSON_CreateObject();
            if (error) {
                cJSON_AddNumberToObject(error, "id", 1000);
                cJSON_AddStringToObject(error, "format", "Invalid variables reference %d - no such variable group exists");
                cJSON_AddNumberToObject(error, "variablesReference", ref);
                cJSON_AddBoolToObject(error, "showUser", true);
                
                // Create response body with error
                cJSON* body = cJSON_CreateObject();
                if (body) {
                    cJSON_AddItemToObject(body, "error", error);
                    char* body_str = cJSON_PrintUnformatted(body);
                    if (body_str) {
                        response->data = body_str;
                        response->data_size = strlen(body_str);
                        cJSON_Delete(body);
                        return 0;
                    }
                    cJSON_Delete(body);
                }
                cJSON_Delete(error);
            }
            set_response_error(response, "Failed to create error response");
            return -1;
        }
    }

    // Add registers as variables if not handling status flags or internal parent scope
    if (ref != 1001 && ref != 4 && reg_array) {
        for (size_t i = 0; i < reg_count; i++) {
            cJSON* var = cJSON_CreateObject();
            if (var) {
                cJSON_AddStringToObject(var, "name", reg_array[i].name);
                char value_str[32];
                if (strcmp(reg_array[i].type, "octal") == 0) {
                    snprintf(value_str, sizeof(value_str), "%o", reg_array[i].value);
                } else {
                    snprintf(value_str, sizeof(value_str), "0x%04x", reg_array[i].value);
                }
                cJSON_AddStringToObject(var, "value", value_str);
                cJSON_AddStringToObject(var, "type", reg_array[i].type);
                cJSON_AddNumberToObject(var, "variablesReference", reg_array[i].nested_ref);
                cJSON_AddStringToObject(var, "presentationHint", "register");
                cJSON_AddItemToArray(variables, var);
            }
        }
    }

    cJSON_AddItemToObject(body, "variables", variables);
    set_response_success(response, body);
    return 0;
}

/*
 * Thread ID Implementation Notes:
 * 
 * The mock debugger implements a simplified thread model where:
 * - Thread ID 1 is the only valid thread ID
 * - This represents the main CPU thread in the ND-100 architecture
 * - The mock debugger does not support multiple threads as the ND-100 is a single-threaded CPU
 * - Thread ID 0 is not used to represent "all threads" as per DAP specification
 * - Instead, the 'singleThread' flag is used to control thread-specific operations
 * 
 * This implementation aligns with the ND-100 architecture while maintaining DAP compliance:
 * - All thread operations default to thread ID 1
 * - Thread-specific operations require thread ID 1
 * - The 'singleThread' flag is properly handled for thread control
 */

static int handle_threads(DAPResponse* response) {
    // Create response body
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }
    
    // Create threads array
    cJSON* threads = cJSON_CreateArray();
    if (!threads) {
        cJSON_Delete(body);
        response->success = false;
        response->error_message = strdup("Failed to create threads array");
        return 0;
    }
    
    // Create thread object
    cJSON* thread = cJSON_CreateObject();
    if (!thread) {
        cJSON_Delete(body);
        cJSON_Delete(threads);
        response->success = false;
        response->error_message = strdup("Failed to create thread object");
        return 0;
    }
    
    // Add thread properties
    cJSON_AddNumberToObject(thread, "id", 1);  // Always use thread ID 1
    cJSON_AddStringToObject(thread, "name", "CPU thread");

    // Add thread state based on debugger state
    if (!mock_debugger.running || !mock_debugger.attached) {
        cJSON_AddStringToObject(thread, "state", "stopped");
    } else if (mock_debugger.paused) {
        cJSON_AddStringToObject(thread, "state", "paused");
    } else {
        cJSON_AddStringToObject(thread, "state", "running");
    }

    // Add thread to array
    cJSON_AddItemToArray(threads, thread);

    // Add threads array to body
    cJSON_AddItemToObject(body, "threads", threads);

    // Convert to string
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        response->success = false;
        response->error_message = strdup("Failed to format response body");
        return 0;
    }
    
    response->success = true;
    response->data = body_str;
    return 0;
}

/*
 * Stack Trace Implementation Notes:
 * 
 * The mock debugger implements a simplified stack trace model where:
 * - Only one stack frame is maintained (the current execution frame)
 * - The frame represents the current program counter (PC) position
 * - Source line information is included when available through line mappings
 * - The stack frame includes:
 *   - Frame ID (always 0 for the single frame)
 *   - Function name (always "main" for the single frame)
 *   - Current line and column from source mapping
 *   - Source file information when available
 * 
 * This implementation reflects the ND-100's simple execution model:
 * - No call stack (no function calls in the traditional sense)
 * - Direct program counter-based execution
 * - Source line mapping for debugging information
 * - Single execution context
 */

static int handle_stack_trace(cJSON* args, DAPResponse* response) {
    if (!mock_debugger.running || !mock_debugger.attached) {
        set_response_error(response, "Debugger is not running or not attached");
        return -1;
    }

    cJSON* body = cJSON_CreateObject();
    if (!body) {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Parse arguments
    int thread_id = 1;  // Default to thread 1
    int start_frame = 0;
    int levels = 1;

    if (args) {
        cJSON* thread_id_json = cJSON_GetObjectItem(args, "threadId");
        if (thread_id_json && cJSON_IsNumber(thread_id_json)) {
            thread_id = thread_id_json->valueint;
        }

        cJSON* start_frame_json = cJSON_GetObjectItem(args, "startFrame");
        if (start_frame_json && cJSON_IsNumber(start_frame_json)) {
            start_frame = start_frame_json->valueint;
        }

        cJSON* levels_json = cJSON_GetObjectItem(args, "levels");
        if (levels_json && cJSON_IsNumber(levels_json)) {
            levels = levels_json->valueint;
        }
    }

    // Validate thread ID
    if (thread_id != 1) {
        cJSON_Delete(body);
        set_response_error(response, "Invalid thread ID - only thread 1 is supported");
        return -1;
    }

    // Validate start_frame and levels
    if (start_frame < 0 || levels < 1) {
        cJSON_Delete(body);
        set_response_error(response, "Invalid start_frame or levels parameter");
        return -1;
    }

    // Create stack frames array
    cJSON* frames = cJSON_CreateArray();
    if (!frames) {
        cJSON_Delete(body);
        set_response_error(response, "Failed to create frames array");
        return -1;
    }

    // Create current frame
    cJSON* frame = cJSON_CreateObject();
    if (!frame) {
        cJSON_Delete(body);
        cJSON_Delete(frames);
        set_response_error(response, "Failed to create frame object");
        return -1;
    }

    // Add frame properties
    cJSON_AddNumberToObject(frame, "id", start_frame);
    cJSON_AddStringToObject(frame, "name", "main");
    cJSON_AddNumberToObject(frame, "line", mock_debugger.current_line);
    cJSON_AddNumberToObject(frame, "column", mock_debugger.current_column);
    
    // Add source information if available
    if (mock_debugger.current_source && mock_debugger.current_source->path) {
        cJSON* source = cJSON_CreateObject();
        if (source) {
            cJSON_AddStringToObject(source, "path", mock_debugger.current_source->path);
            cJSON_AddItemToObject(frame, "source", source);
        }
    }
    
    // Add frame to array
    cJSON_AddItemToArray(frames, frame);

    // Add frames array to body
    cJSON_AddItemToObject(body, "stackFrames", frames);

    // Add total frames count (limited by levels parameter)
    cJSON_AddNumberToObject(body, "totalFrames", levels > 1 ? levels : 1);

    // Set response
    set_response_success(response, body);
    cJSON_Delete(body);
    return 0;
}

// Implement missing functions
// static int handle_evaluate(cJSON* args, DAPResponse* response) { ... }
// static int handle_set_variable(cJSON* args, DAPResponse* response) { ... }
// static int handle_set_expression(cJSON* args, DAPResponse* response) { ... }
// static int handle_loaded_sources(cJSON* args, DAPResponse* response) { ... }
// static int handle_modules(cJSON* args, DAPResponse* response) { ... }
// static int handle_disassemble(cJSON* args, DAPResponse* response) { ... }
// static int handle_step_back(cJSON* args, DAPResponse* response) { ... }
// static int handle_set_instruction_breakpoints(cJSON* args, DAPResponse* response) { ... }
// static int handle_set_data_breakpoints(cJSON* args, DAPResponse* response) { ... }
// static int handle_exception_info(cJSON* args, DAPResponse* response) { ... }

// Implement missing functions from dbg_mock.h
int dbg_mock_init(int port) {
    // Initialize mock debugger state
    mock_debugger.running = false;
    mock_debugger.attached = false;
    mock_debugger.paused = false;
    mock_debugger.program_path = NULL;
    mock_debugger.current_thread = 1;
    mock_debugger.pc = 0;
    mock_debugger.breakpoint_count = 0;
    mock_debugger.breakpoints = NULL;
    mock_debugger.current_source = NULL;
    mock_debugger.current_line = 0;
    mock_debugger.current_column = 0;
    mock_debugger.last_event = DAP_EVENT_NONE;
    mock_debugger.memory_size = 0;
    mock_debugger.memory = NULL;
    mock_debugger.register_count = 0;
    mock_debugger.registers = NULL;
    mock_debugger.line_map_count = 0;
    mock_debugger.line_maps = NULL;

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
        },
        .callbacks = {
            .handle_command = mock_handle_command,
            .handle_event = handle_event
        },
        .user_data = &mock_debugger,
        .stop_at_entry = false,
        .program_path = NULL
    };

    mock_debugger.server = dap_server_create(&config);
    if (!mock_debugger.server) {
        return -1;
    }

    return 0;
}

int dbg_mock_start(void) {
    if (!mock_debugger.server) {
        return -1;
    }

    return dap_server_start(mock_debugger.server);
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

    if (mock_debugger.breakpoints) {
        free(mock_debugger.breakpoints);
        mock_debugger.breakpoints = NULL;
    }

    if (mock_debugger.memory) {
        free(mock_debugger.memory);
        mock_debugger.memory = NULL;
    }

    if (mock_debugger.registers) {
        free(mock_debugger.registers);
        mock_debugger.registers = NULL;
    }

    cleanup_line_maps(&mock_debugger);
}

void dbg_mock_set_program_path(const char* path) {
    mock_debugger.program_path = path;
}

uint32_t dbg_mock_get_pc(void) {
    return mock_debugger.pc;
}

void dbg_mock_set_pc(uint32_t pc) {
    mock_debugger.pc = pc;
}

int dbg_mock_get_current_thread(void) {
    return mock_debugger.current_thread;
}

void dbg_mock_set_current_thread(int thread_id) {
    mock_debugger.current_thread = thread_id;
}

bool dbg_mock_is_running(void) {
    return mock_debugger.running;
}

void dbg_mock_set_running(bool running) {
    mock_debugger.running = running;
}

bool dbg_mock_is_attached(void) {
    return mock_debugger.attached;
}

void dbg_mock_set_attached(bool attached) {
    mock_debugger.attached = attached;
}

int dbg_mock_add_breakpoint(int line, int column) {
    if (mock_debugger.breakpoint_count >= MAX_BREAKPOINTS) {
        return -1;
    }

    // Check if breakpoint already exists
    for (int i = 0; i < mock_debugger.breakpoint_count; i++) {
        if (mock_debugger.breakpoints[i].line == line && 
            mock_debugger.breakpoints[i].column == column) {
            return 0;  // Breakpoint already exists
        }
    }

    // Reallocate breakpoints array
    DAPBreakpoint* new_breakpoints = realloc(mock_debugger.breakpoints, 
                                           (mock_debugger.breakpoint_count + 1) * sizeof(DAPBreakpoint));
    if (!new_breakpoints) {
        return -1;
    }

    mock_debugger.breakpoints = new_breakpoints;
    mock_debugger.breakpoints[mock_debugger.breakpoint_count].line = line;
    mock_debugger.breakpoints[mock_debugger.breakpoint_count].column = column;
    mock_debugger.breakpoint_count++;

    return 0;
}

int dbg_mock_remove_breakpoint(int line, int column) {
    for (int i = 0; i < mock_debugger.breakpoint_count; i++) {
        if (mock_debugger.breakpoints[i].line == line && 
            mock_debugger.breakpoints[i].column == column) {
            // Shift remaining breakpoints
            for (int j = i; j < mock_debugger.breakpoint_count - 1; j++) {
                mock_debugger.breakpoints[j] = mock_debugger.breakpoints[j + 1];
            }
            mock_debugger.breakpoint_count--;
            return 0;
        }
    }
    return -1;
}

bool dbg_mock_has_breakpoint(int line, int column) {
    for (int i = 0; i < mock_debugger.breakpoint_count; i++) {
        if (mock_debugger.breakpoints[i].line == line && 
            mock_debugger.breakpoints[i].column == column) {
            return true;
        }
    }
    return false;
}

int dbg_mock_get_breakpoint_count(void) {
    return mock_debugger.breakpoint_count;
}

DAPBreakpoint* dbg_mock_get_breakpoint(size_t index) {
    if (index >= (size_t)mock_debugger.breakpoint_count) {
        return NULL;
    }
    return &mock_debugger.breakpoints[index];
}

// Move cleanup_line_maps function before its usage
static void cleanup_line_maps(MockDebugger* debugger) {
    if (debugger->line_maps) {
        for (int i = 0; i < debugger->line_map_count; i++) {
            free((void*)debugger->line_maps[i].file_path);
        }
        free(debugger->line_maps);
        debugger->line_maps = NULL;
        debugger->line_map_count = 0;
        debugger->line_map_capacity = 0;
    }
}

// Add new public function for adding line mappings
void dbg_mock_add_line_map(const char* file_path, int line, uint32_t address) {
    add_line_map(file_path, line, address);
}

// Update cleanup_breakpoints to use MockDebugger
static void cleanup_breakpoints(MockDebugger* debugger) {
    if (debugger->breakpoints) {
        for (int i = 0; i < debugger->breakpoint_count; i++) {
            if (debugger->breakpoints[i].source) {
                free(debugger->breakpoints[i].source->path);
                free(debugger->breakpoints[i].source);
            }
        }
        free(debugger->breakpoints);
        debugger->breakpoints = NULL;
        debugger->breakpoint_count = 0;
    }
}

// Implement missing handler functions
static int handle_configuration_done(DAPResponse* response) {
    if (!response) return -1;
    response->success = true;
    response->data = strdup("{}");
    return 0;
}

static int handle_continue(cJSON* args, DAPResponse* response) {
    (void)args;  // Mark as unused
    if (!mock_debugger.running || !mock_debugger.attached) {
        set_response_error(response, "Debugger not running or attached");
        return -1;
    }

    if (!mock_debugger.paused) {
        set_response_error(response, "Debugger not paused");
        return -1;
    }

    // Create success response
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    cJSON_AddBoolToObject(body, "allThreadsContinued", true);

    set_response_success(response, body);
    cJSON_Delete(body);

    mock_debugger.paused = false;

    // Send continued event according to DAP spec
    DAPServer* server = (DAPServer*)mock_debugger.server;
    if (server && server->config.callbacks.handle_event) {
        cJSON* event_body = cJSON_CreateObject();
        if (event_body) {
            cJSON_AddNumberToObject(event_body, "threadId", mock_debugger.current_thread);
            cJSON_AddBoolToObject(event_body, "allThreadsContinued", true);
            
            char* event_body_str = cJSON_PrintUnformatted(event_body);
            if (event_body_str) {
                server->config.callbacks.handle_event(server->config.user_data,
                                                   DAP_EVENT_CONTINUED,
                                                   event_body_str);
                free(event_body_str);
            }
            cJSON_Delete(event_body);
        }
    }

    return 0;
}

static int handle_next(cJSON* args, DAPResponse* response) {
    (void)args;  // Mark as unused
    if (!mock_debugger.running || !mock_debugger.attached) {
        response->success = false;
        response->error_message = strdup("Debugger not running or attached");
        return 0;
    }

    if (!mock_debugger.paused) {
        response->success = false;
        response->error_message = strdup("Debugger not paused");
        return 0;
    }

    // Create response body
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    cJSON_AddBoolToObject(body, "allThreadsStopped", true);

    // Convert to string
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        response->success = false;
        response->error_message = strdup("Failed to format response body");
        return 0;
    }

    // Simulate stepping over
    mock_debugger.pc += 4; // Assuming 4-byte instructions
    int line = get_line_for_address(mock_debugger.pc);
    if (line > 0) {
        mock_debugger.current_line = line;
    }

    response->success = true;
    response->data = body_str;

    // Send stopped event according to DAP spec
    DAPServer* server = (DAPServer*)mock_debugger.server;
    if (server && server->config.callbacks.handle_event) {
        cJSON* event_body = cJSON_CreateObject();
        if (event_body) {
            cJSON_AddStringToObject(event_body, "reason", "step");
            cJSON_AddNumberToObject(event_body, "threadId", mock_debugger.current_thread);
            cJSON_AddBoolToObject(event_body, "allThreadsStopped", true);
            cJSON_AddStringToObject(event_body, "description", "Stepped over instruction");
            
            if (mock_debugger.current_source) {
                cJSON* source = cJSON_CreateObject();
                if (source) {
                    cJSON_AddStringToObject(source, "name", mock_debugger.current_source->name);
                    cJSON_AddStringToObject(source, "path", mock_debugger.current_source->path);
                    cJSON_AddItemToObject(event_body, "source", source);
                }
            }
            
            // Add line information if available
            if (line > 0) {
                cJSON_AddNumberToObject(event_body, "line", line);
                cJSON_AddNumberToObject(event_body, "column", mock_debugger.current_column);
            }
            
            char* event_body_str = cJSON_PrintUnformatted(event_body);
            if (event_body_str) {
                server->config.callbacks.handle_event(server->config.user_data,
                                                   DAP_EVENT_STOPPED,
                                                   event_body_str);
                free(event_body_str);
            }
            cJSON_Delete(event_body);
        }
    }

    return 0;
}

static int handle_step_in(cJSON* args, DAPResponse* response) {
    if (!mock_debugger.running || !mock_debugger.attached) {
        response->success = false;
        response->error_message = strdup("Debugger not running or attached");
        return 0;
    }

    if (!mock_debugger.paused) {
        response->success = false;
        response->error_message = strdup("Debugger not paused");
        return 0;
    }

    // Parse arguments
    int thread_id = -1;
    bool single_thread = false;
    int target_id = -1;
    const char* granularity = NULL;

    cJSON* thread_id_json = cJSON_GetObjectItem(args, "threadId");
    if (thread_id_json && cJSON_IsNumber(thread_id_json)) {
        thread_id = thread_id_json->valueint;
    }

    cJSON* single_thread_json = cJSON_GetObjectItem(args, "singleThread");
    if (single_thread_json && cJSON_IsBool(single_thread_json)) {
        single_thread = cJSON_IsTrue(single_thread_json);
    }

    cJSON* target_id_json = cJSON_GetObjectItem(args, "targetId");
    if (target_id_json && cJSON_IsNumber(target_id_json)) {
        target_id = target_id_json->valueint;
    }

    cJSON* granularity_json = cJSON_GetObjectItem(args, "granularity");
    if (granularity_json && cJSON_IsString(granularity_json)) {
        granularity = granularity_json->valuestring;
    }

    // Validate thread ID
    if (thread_id < 0) {
        response->success = false;
        response->error_message = strdup("Invalid thread ID");
        return 0;
    }

    // Create response body
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    cJSON_AddBoolToObject(body, "allThreadsStopped", !single_thread);

    // Convert to string
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        response->success = false;
        response->error_message = strdup("Failed to format response body");
        return 0;
    }

    // Simulate stepping in based on granularity
    if (granularity && strcmp(granularity, "instruction") == 0) {
        mock_debugger.pc += 4; // Single instruction step
    } else {
        // Default to statement/line granularity
        mock_debugger.pc += 8; // Step to next statement/line
    }

    // Update line information
    int line = get_line_for_address(mock_debugger.pc);
    if (line > 0) {
        mock_debugger.current_line = line;
    }

    response->success = true;
    response->data = body_str;

    // Send stopped event according to DAP spec
    DAPServer* server = (DAPServer*)mock_debugger.server;
    if (server && server->config.callbacks.handle_event) {
        cJSON* event_body = cJSON_CreateObject();
        if (event_body) {
            cJSON_AddStringToObject(event_body, "reason", "step");
            cJSON_AddNumberToObject(event_body, "threadId", thread_id);
            cJSON_AddBoolToObject(event_body, "allThreadsStopped", !single_thread);
            cJSON_AddStringToObject(event_body, "description", "Stepped into instruction");
            
            if (mock_debugger.current_source) {
                cJSON* source = cJSON_CreateObject();
                if (source) {
                    cJSON_AddStringToObject(source, "name", mock_debugger.current_source->name);
                    cJSON_AddStringToObject(source, "path", mock_debugger.current_source->path);
                    cJSON_AddItemToObject(event_body, "source", source);
                }
            }
            
            // Add line information if available
            if (line > 0) {
                cJSON_AddNumberToObject(event_body, "line", line);
                cJSON_AddNumberToObject(event_body, "column", mock_debugger.current_column);
            }
            
            char* event_body_str = cJSON_PrintUnformatted(event_body);
            if (event_body_str) {
                server->config.callbacks.handle_event(server->config.user_data,
                                                   DAP_EVENT_STOPPED,
                                                   event_body_str);
                free(event_body_str);
            }
            cJSON_Delete(event_body);
        }
    }

    return 0;
}

static int handle_step_out(cJSON* args, DAPResponse* response) {
    (void)args;  // Mark as unused
    if (!mock_debugger.running || !mock_debugger.attached) {
        response->success = false;
        response->error_message = strdup("Debugger not running or attached");
        return 0;
    }

    if (!mock_debugger.paused) {
        response->success = false;
        response->error_message = strdup("Debugger not paused");
        return 0;
    }

    // Create response body
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    cJSON_AddBoolToObject(body, "allThreadsStopped", true);

    // Convert to string
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        response->success = false;
        response->error_message = strdup("Failed to format response body");
        return 0;
    }

    // Simulate stepping out
    mock_debugger.pc += 4; // Assuming 4-byte instructions
    int line = get_line_for_address(mock_debugger.pc);
    if (line > 0) {
        mock_debugger.current_line = line;
    }

    response->success = true;
    response->data = body_str;

    // Send stopped event according to DAP spec
    DAPServer* server = (DAPServer*)mock_debugger.server;
    if (server && server->config.callbacks.handle_event) {
        cJSON* event_body = cJSON_CreateObject();
        if (event_body) {
            cJSON_AddStringToObject(event_body, "reason", "step");
            cJSON_AddNumberToObject(event_body, "threadId", mock_debugger.current_thread);
            cJSON_AddBoolToObject(event_body, "allThreadsStopped", true);
            cJSON_AddStringToObject(event_body, "description", "Stepped out of function");
            
            if (mock_debugger.current_source) {
                cJSON* source = cJSON_CreateObject();
                if (source) {
                    cJSON_AddStringToObject(source, "name", mock_debugger.current_source->name);
                    cJSON_AddStringToObject(source, "path", mock_debugger.current_source->path);
                    cJSON_AddItemToObject(event_body, "source", source);
                }
            }
            
            // Add line information if available
            if (line > 0) {
                cJSON_AddNumberToObject(event_body, "line", line);
                cJSON_AddNumberToObject(event_body, "column", mock_debugger.current_column);
            }
            
            char* event_body_str = cJSON_PrintUnformatted(event_body);
            if (event_body_str) {
                server->config.callbacks.handle_event(server->config.user_data,
                                                   DAP_EVENT_STOPPED,
                                                   event_body_str);
                free(event_body_str);
            }
            cJSON_Delete(event_body);
        }
    }

    return 0;
}

static int handle_read_memory(cJSON* args, DAPResponse* response) {
    (void)args;  // Mark as unused
    if (!mock_debugger.running || !mock_debugger.attached) {
        response->success = false;
        response->error_message = strdup("Debugger not running or attached");
        return 0;
    }

    // Get memory read parameters
    cJSON* address_json = cJSON_GetObjectItem(args, "address");
    cJSON* count_json = cJSON_GetObjectItem(args, "count");
    if (!address_json || !count_json) {
        response->success = false;
        response->error_message = strdup("Missing required parameters");
        return 0;
    }

    uint64_t address = address_json->valueint;
    int count = count_json->valueint;

    // Validate parameters
    if (count <= 0 || count > 1024) {
        response->success = false;
        response->error_message = strdup("Invalid count parameter");
        return 0;
    }

    // Create response body
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    // Simulate memory read
    char* data = (char*)malloc(count);
    if (!data) {
        cJSON_Delete(body);
        response->success = false;
        response->error_message = strdup("Failed to allocate memory");
        return 0;
    }

    // Fill with mock data
    for (int i = 0; i < count; i++) {
        data[i] = (char)((address + i) & 0xFF);
    }

    // Add to response
    char address_str[32];
    snprintf(address_str, sizeof(address_str), "0x%lx", address);
    cJSON_AddStringToObject(body, "address", address_str);
    cJSON_AddNumberToObject(body, "unreadableBytes", 0);
    cJSON_AddStringToObject(body, "data", data);
    free(data);

    // Convert to string
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        response->success = false;
        response->error_message = strdup("Failed to format response body");
        return 0;
    }

    response->success = true;
    response->data = body_str;
    return 0;
}

static int handle_write_memory(cJSON* args, DAPResponse* response) {
    (void)args;  // Mark as unused
    if (!mock_debugger.running || !mock_debugger.attached) {
        response->success = false;
        response->error_message = strdup("Debugger not running or attached");
        return 0;
    }

    // Get memory write parameters
    cJSON* address_json = cJSON_GetObjectItem(args, "address");
    cJSON* data_json = cJSON_GetObjectItem(args, "data");
    if (!address_json || !data_json) {
        response->success = false;
        response->error_message = strdup("Missing required parameters");
        return 0;
    }

    // Create response body
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    // Simulate memory write
    cJSON_AddNumberToObject(body, "bytesWritten", strlen(data_json->valuestring));

    // Convert to string
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        response->success = false;
        response->error_message = strdup("Failed to format response body");
        return 0;
    }

    response->success = true;
    response->data = body_str;
    return 0;
}

static int handle_read_registers(cJSON* args, DAPResponse* response) {
    (void)args;  // Mark as unused
    if (!mock_debugger.running || !mock_debugger.attached) {
        response->success = false;
        response->error_message = strdup("Debugger not running or attached");
        return 0;
    }

    // Create response body
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    // Create registers array
    cJSON* registers = cJSON_CreateArray();
    if (!registers) {
        cJSON_Delete(body);
        response->success = false;
        response->error_message = strdup("Failed to create registers array");
        return 0;
    }

    // Add CPU registers
    for (size_t i = 0; i < NUM_REGISTERS; i++) {
        cJSON* reg = cJSON_CreateObject();
        if (!reg) {
            cJSON_Delete(registers);
            cJSON_Delete(body);
            response->success = false;
            response->error_message = strdup("Failed to create register object");
            return 0;
        }

        cJSON_AddStringToObject(reg, "name", cpu_registers[i].name);
        char value_str[32];
        snprintf(value_str, sizeof(value_str), "0x%04x", cpu_registers[i].value);
        cJSON_AddStringToObject(reg, "value", value_str);
        cJSON_AddStringToObject(reg, "type", cpu_registers[i].type);
        if (cpu_registers[i].has_nested) {
            cJSON_AddNumberToObject(reg, "variablesReference", cpu_registers[i].nested_ref);
        }
        cJSON_AddItemToArray(registers, reg);
    }

    cJSON_AddItemToObject(body, "registers", registers);

    // Convert to string
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        response->success = false;
        response->error_message = strdup("Failed to format response body");
        return 0;
    }

    response->success = true;
    response->data = body_str;
    return 0;
}

static int handle_write_register(cJSON* args, DAPResponse* response) {
    (void)args;  // Mark as unused
    if (!mock_debugger.running || !mock_debugger.attached) {
        response->success = false;
        response->error_message = strdup("Debugger not running or attached");
        return 0;
    }

    // Get register write parameters
    cJSON* name_json = cJSON_GetObjectItem(args, "name");
    cJSON* value_json = cJSON_GetObjectItem(args, "value");
    if (!name_json || !value_json) {
        response->success = false;
        response->error_message = strdup("Missing required parameters");
        return 0;
    }

    const char* name = name_json->valuestring;
    const char* value = value_json->valuestring;

    // Find register in CPU registers
    int reg_index = -1;
    for (size_t i = 0; i < NUM_REGISTERS; i++) {
        if (strcmp(name, cpu_registers[i].name) == 0) {
            reg_index = i;
            break;
        }
    }

    if (reg_index == -1) {
        response->success = false;
        response->error_message = strdup("Invalid register name");
        return 0;
    }

    // Parse value based on register type
    uint16_t reg_value;
    if (strcmp(cpu_registers[reg_index].type, "octal") == 0) {
        if (sscanf(value, "%ho", &reg_value) != 1) {
            response->success = false;
            response->error_message = strdup("Invalid octal value");
            return 0;
        }
    } else {
        if (sscanf(value, "0x%hx", &reg_value) != 1) {
            response->success = false;
            response->error_message = strdup("Invalid hex value");
            return 0;
        }
    }

    // Update register
    cpu_registers[reg_index].value = reg_value;

    // Create response body
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    // Convert to string
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        response->success = false;
        response->error_message = strdup("Failed to format response body");
        return 0;
    }

    response->success = true;
    response->data = body_str;
    return 0;
}

int handle_pause(cJSON* args, DAPResponse* response) {
    if (!mock_debugger.running || !mock_debugger.attached) {
        response->success = false;
        response->error_message = strdup("Debugger not running or attached");
        return 0;
    }

    if (mock_debugger.paused) {
        response->success = false;
        response->error_message = strdup("Debugger already paused");
        return 0;
    }

    // Parse arguments
    int thread_id = -1;
    cJSON* thread_id_json = cJSON_GetObjectItem(args, "threadId");
    if (thread_id_json && cJSON_IsNumber(thread_id_json)) {
        thread_id = thread_id_json->valueint;
    }

    // Validate thread ID
    if (thread_id < 0) {
        response->success = false;
        response->error_message = strdup("Invalid thread ID");
        return 0;
    }

    // Create response body
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    cJSON_AddBoolToObject(body, "allThreadsStopped", true);

    // Convert to string
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        response->success = false;
        response->error_message = strdup("Failed to format response body");
        return 0;
    }

    // Update debugger state
    mock_debugger.paused = true;
    mock_debugger.current_thread = thread_id;

    response->success = true;
    response->data = body_str;

    // Send stopped event according to DAP spec
    DAPServer* server = (DAPServer*)mock_debugger.server;
    if (server && server->config.callbacks.handle_event) {
        cJSON* event_body = cJSON_CreateObject();
        if (event_body) {
            cJSON_AddStringToObject(event_body, "reason", "pause");
            cJSON_AddNumberToObject(event_body, "threadId", thread_id);
            cJSON_AddBoolToObject(event_body, "allThreadsStopped", true);
            cJSON_AddStringToObject(event_body, "description", "Thread paused by user");
            
            if (mock_debugger.current_source) {
                cJSON* source = cJSON_CreateObject();
                if (source) {
                    cJSON_AddStringToObject(source, "name", mock_debugger.current_source->name);
                    cJSON_AddStringToObject(source, "path", mock_debugger.current_source->path);
                    cJSON_AddItemToObject(event_body, "source", source);
                }
            }
            
            // Add line information if available
            if (mock_debugger.current_line > 0) {
                cJSON_AddNumberToObject(event_body, "line", mock_debugger.current_line);
                cJSON_AddNumberToObject(event_body, "column", mock_debugger.current_column);
            }
            
            char* event_body_str = cJSON_PrintUnformatted(event_body);
            if (event_body_str) {
                server->config.callbacks.handle_event(server->config.user_data,
                                                   DAP_EVENT_STOPPED,
                                                   event_body_str);
                free(event_body_str);
            }
            cJSON_Delete(event_body);
        }
    }

    return 0;
}

