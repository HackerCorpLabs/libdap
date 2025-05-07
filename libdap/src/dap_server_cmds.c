/**
 * @file dap_server_cmds.c
 * @brief Server implementation for the DAP library
 */

#include <stdarg.h> // For va_list, va_start, va_end
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>

#include "dap_server.h"
#include "dap_error.h"
#include "dap_types.h"
#include "dap_transport.h"
#include "dap_protocol.h"
#include "dap_server_cmds.h"
#include <cjson/cJSON.h>

#define MAX_PATH_LENGTH 1024  // Define a safe maximum path length

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
 * @brief Encodes binary data as a base64 string
 * 
 * This implementation is a simple helper for the DAP protocol which requires
 * memory data to be base64 encoded in readMemory responses.
 * 
 * @param data The binary data to encode
 * @param len The length of the data in bytes
 * @return char* The base64 encoded string (caller must free)
 */
static char* base64_encode(const uint8_t* data, size_t len) {
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    // Calculate the length of the output string
    size_t output_len = 4 * ((len + 2) / 3) + 1; // +1 for null terminator
    
    // Allocate memory for the output
    char* output = malloc(output_len);
    if (!output) {
        return NULL;
    }
    
    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        uint32_t triplet = data[i] << 16;
        if (i + 1 < len) triplet |= data[i + 1] << 8;
        if (i + 2 < len) triplet |= data[i + 2];
        
        output[j] = base64_chars[(triplet >> 18) & 0x3F];
        output[j + 1] = base64_chars[(triplet >> 12) & 0x3F];
        output[j + 2] = (i + 1 < len) ? base64_chars[(triplet >> 6) & 0x3F] : '=';
        output[j + 3] = (i + 2 < len) ? base64_chars[triplet & 0x3F] : '=';
    }
    
    output[j] = '\0';
    return output;
}

// Define CPU registers for ND-100
static Register cpu_registers[] = {
    {"STS", 0x0000, "bitmask", true, 1001}, // Status register with nested flags
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

// Forward declarations for helper functions
void free_breakpoints_array(const DAPBreakpoint *breakpoints, int count);
void free_filter_arrays(const char **filter_ids, const char **filter_conditions, int count);
static void set_response_success(DAPResponse *response, cJSON *body);
static void set_response_error(DAPResponse *response, const char *error_message);

/**
 * @brief Send the 'initialized' event to the client
 * This event should be sent after the successful response to an 'initialize' request
 * @param server Server instance
 * @return 0 on success, non-zero on failure
 */
int send_initialized_event(DAPServer *server)
{
    if (!server)
    {
        return -1;
    }

    // Create empty body - the initialized event doesn't need any additional data
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        return -1;
    }

    // Send the event
    int result = dap_server_send_event(server, "initialized", body);
    
    // Clean up
    cJSON_Delete(body);
    
    return result;
}

/**
 * @brief Structure representing a single server capability
 */
typedef struct {
    const char *name;     // Name of the capability in the DAP spec
    bool supported;       // Whether the capability is supported
} DAPCapability;

/**
 * @brief Global array of server capabilities
 * Indexed by DAPCapabilityID enum values
 * All capabilities are initialized as false by default
 */
static DAPCapability server_capabilities[DAP_CAP_COUNT] = {
    {"supportsConfigurationDoneRequest",      false},
    {"supportsFunctionBreakpoints",           false},
    {"supportsConditionalBreakpoints",        false},
    {"supportsHitConditionalBreakpoints",     false},
    {"supportsEvaluateForHovers",             false},
    {"supportsSetVariable",                   false},
    {"supportsCompletionsRequest",            false},
    {"supportsModulesRequest",                false},
    {"supportsRestartRequest",                false},
    {"supportsExceptionOptions",              false},
    {"supportsValueFormattingOptions",        false},
    {"supportsExceptionInfoRequest",          false},
    {"supportTerminateDebuggee",              false},  // NOTE! This is not the same as terminateRequest. And be aware of the single vs plural in the name. Its single!
    {"supportsDelayedStackTraceLoading",      false},
    {"supportsLoadedSourcesRequest",          false},
    {"supportsLogPoints",                     false},
    {"supportsTerminateThreadsRequest",       false},
    {"supportsSetExpression",                 false},
    {"supportsTerminateRequest",              false},
    {"supportsDataBreakpoints",               false},
    {"supportsReadMemoryRequest",             false},
    {"supportsWriteMemoryRequest",            false},
    {"supportsDisassembleRequest",            false},
    {"supportsCancelRequest",                 false},
    {"supportsBreakpointLocationsRequest",    false},
    {"supportsSteppingGranularity",           false},
    {"supportsInstructionBreakpoints",        false},
    {"supportsExceptionFilterOptions",        false},
    {"supportsSingleThreadExecutionRequests", false},
    {"supportsStepBack",                      false},
    {"supportsRestartFrame",                  false},
    {"supportsGotoTargetsRequest",            false},
    {"supportsStepInTargetsRequest",          false},
    {"supportsClipboardContext",              false},
};

/**
 * @brief Set a capability in the capability array
 * 
 * @param capability_id The capability enum value to set
 * @param supported Whether the capability is supported
 * @return int 0 on success, -1 if capability_id is out of range
 */
int dap_server_set_capability(DAPCapabilityID capability_id, bool supported)
{
    if (capability_id >= 0 && capability_id < DAP_CAP_COUNT) {
        server_capabilities[capability_id].supported = supported;
        return 0;
    }
    return -1;
}

/**
 * @brief Enum for DAP exception filter types
 * 
 * Per DAP specification, an ExceptionBreakpointsFilter represents a specific way of handling 
 * exceptions that can be enabled or disabled by the client. Each filter is shown in the UI
 * as a checkbox option for configuring how exceptions are dealt with during debugging.
 */
typedef enum {
    DAP_EXC_FILTER_ALL,      // Breaks when any exception is thrown, whether caught or not
    DAP_EXC_FILTER_UNCAUGHT, // Breaks only on exceptions that aren't caught by user code
    
    // Keep this last to get the total count of filters
    DAP_EXC_FILTER_COUNT
    
    /* To add new exception filters:
     * 1. Add a new enum value above DAP_EXC_FILTER_COUNT
     * 2. Add a corresponding entry in the exception_filters array
     */
} DAPExceptionFilterID;

/**
 * @brief Structure representing an exception breakpoint filter
 * 
 * According to DAP spec, these filters are exposed to the client during initialization 
 * as part of the 'exceptionBreakpointFilters' capability. The client UI shows each filter
 * as an option that can be enabled/disabled. When enabled, the debug adapter will break
 * execution when exceptions matching the filter criteria are thrown.
 */
typedef struct {
    const char *id;          // Filter ID used in requests (matches the filter in enum)
    const char *label;       // Human-readable filter name shown in the UI
    const char *description; // Description of when this filter applies
    bool default_value;      // Whether this filter is enabled by default
} DAPExceptionFilter;

/**
 * @brief Global array of exception filters
 * Indexed by DAPExceptionFilterID enum values
 */
static const DAPExceptionFilter exception_filters[DAP_EXC_FILTER_COUNT] = {
    {"all",      "All Exceptions",       "Break on all exceptions",           false},
    {"uncaught", "Uncaught Exceptions",  "Break on uncaught exceptions",      true},
};



/**
 * @brief Set multiple capabilities at once
 * 
 * This function accepts a variable number of capability ID and boolean pairs,
 * terminated by DAP_CAP_COUNT. For example:
 * 
 * dap_server_set_capabilities(
 *     DAP_CAP_CONFIG_DONE_REQUEST, true,
 *     DAP_CAP_FUNCTION_BREAKPOINTS, true,
 *     DAP_CAP_CONDITIONAL_BREAKPOINTS, true,
 *     DAP_CAP_COUNT  // Terminator
 * );
 * 
 * @param ... Variable number of DAPCapabilityID and boolean pairs, terminated by DAP_CAP_COUNT
 * @return int The number of capabilities actually set
 */
int dap_server_set_capabilities(DAPServer *server, ...)
{
    (void)server; // Parameter currently unused, but included for future use
    
    va_list args;
    va_start(args, server);
    
    int count = 0;
    DAPCapabilityID capability_id;
    
    while ((capability_id = va_arg(args, DAPCapabilityID)) != DAP_CAP_COUNT) {
        bool supported = va_arg(args, int);  // bool is promoted to int in va_arg
        if (dap_server_set_capability(capability_id, supported) == 0) {
            count++;
        }
    }
    
    va_end(args);
    return count;
}

/// @brief Handle the DAP initialize command
/// @param server
/// @param args
/// @param response
/// @return
int handle_initialize(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!response || !server)
    {
        return -1;
    }

    // Store client capabilities if provided
    if (args)
    {
        // Parse and store important client capabilities
        cJSON *client_id = cJSON_GetObjectItem(args, "clientID");
        if (client_id && cJSON_IsString(client_id)) {
            if (server->client_capabilities.clientID) {
                free(server->client_capabilities.clientID);
            }
            server->client_capabilities.clientID = strdup(client_id->valuestring);
        }
        
        cJSON *client_name = cJSON_GetObjectItem(args, "clientName");
        if (client_name && cJSON_IsString(client_name)) {
            if (server->client_capabilities.clientName) {
                free(server->client_capabilities.clientName);
            }
            server->client_capabilities.clientName = strdup(client_name->valuestring);
        }
        
        cJSON *adapter_id = cJSON_GetObjectItem(args, "adapterID");
        if (adapter_id && cJSON_IsString(adapter_id)) {
            if (server->client_capabilities.adapterID) {
                free(server->client_capabilities.adapterID);
            }
            server->client_capabilities.adapterID = strdup(adapter_id->valuestring);
        }
        
        cJSON *locale = cJSON_GetObjectItem(args, "locale");
        if (locale && cJSON_IsString(locale)) {
            if (server->client_capabilities.locale) {
                free(server->client_capabilities.locale);
            }
            server->client_capabilities.locale = strdup(locale->valuestring);
        }
        
        // Store path format (path or uri)
        cJSON *path_format = cJSON_GetObjectItem(args, "pathFormat");
        if (path_format && cJSON_IsString(path_format)) {
            if (server->client_capabilities.pathFormat) {
                free(server->client_capabilities.pathFormat);
            }
            server->client_capabilities.pathFormat = strdup(path_format->valuestring);
        }
        
        // Store line/column formatting preferences
        cJSON *lines_start_at_1 = cJSON_GetObjectItem(args, "linesStartAt1");
        if (lines_start_at_1 && cJSON_IsBool(lines_start_at_1)) {
            server->client_capabilities.linesStartAt1 = cJSON_IsTrue(lines_start_at_1);
        } else {
            server->client_capabilities.linesStartAt1 = true; // Default to 1-based
        }
        
        cJSON *columns_start_at_1 = cJSON_GetObjectItem(args, "columnsStartAt1");
        if (columns_start_at_1 && cJSON_IsBool(columns_start_at_1)) {
            server->client_capabilities.columnsStartAt1 = cJSON_IsTrue(columns_start_at_1);
        } else {
            server->client_capabilities.columnsStartAt1 = true; // Default to 1-based
        }
        
        // Store supported client features
        cJSON *supports_variable_type = cJSON_GetObjectItem(args, "supportsVariableType");
        if (supports_variable_type && cJSON_IsBool(supports_variable_type)) {
            server->client_capabilities.supportsVariableType = cJSON_IsTrue(supports_variable_type);
        }
        
        cJSON *supports_variable_paging = cJSON_GetObjectItem(args, "supportsVariablePaging");
        if (supports_variable_paging && cJSON_IsBool(supports_variable_paging)) {
            server->client_capabilities.supportsVariablePaging = cJSON_IsTrue(supports_variable_paging);
        }
        
        cJSON *supports_run_in_terminal = cJSON_GetObjectItem(args, "supportsRunInTerminalRequest");
        if (supports_run_in_terminal && cJSON_IsBool(supports_run_in_terminal)) {
            server->client_capabilities.supportsRunInTerminalRequest = cJSON_IsTrue(supports_run_in_terminal);
        }
        
        cJSON *supports_memory_references = cJSON_GetObjectItem(args, "supportsMemoryReferences");
        if (supports_memory_references && cJSON_IsBool(supports_memory_references)) {
            server->client_capabilities.supportsMemoryReferences = cJSON_IsTrue(supports_memory_references);
        }
        
        cJSON *supports_progress_reporting = cJSON_GetObjectItem(args, "supportsProgressReporting");
        if (supports_progress_reporting && cJSON_IsBool(supports_progress_reporting)) {
            server->client_capabilities.supportsProgressReporting = cJSON_IsTrue(supports_progress_reporting);
        }
        
        cJSON *supports_invalidated_event = cJSON_GetObjectItem(args, "supportsInvalidatedEvent");
        if (supports_invalidated_event && cJSON_IsBool(supports_invalidated_event)) {
            server->client_capabilities.supportsInvalidatedEvent = cJSON_IsTrue(supports_invalidated_event);
        }
        
        cJSON *supports_memory_event = cJSON_GetObjectItem(args, "supportsMemoryEvent");
        if (supports_memory_event && cJSON_IsBool(supports_memory_event)) {
            server->client_capabilities.supportsMemoryEvent = cJSON_IsTrue(supports_memory_event);
        }

        cJSON *supports_ansi_styling = cJSON_GetObjectItem(args, "supportsANSIStyling");
        if (supports_ansi_styling && cJSON_IsBool(supports_ansi_styling)) {
            server->client_capabilities.supportsANSIStyling = cJSON_IsTrue(supports_ansi_styling);
        }
        
        cJSON *supports_args_shell = cJSON_GetObjectItem(args, "supportsArgsCanBeInterpretedByShell");
        if (supports_args_shell && cJSON_IsBool(supports_args_shell)) {
            server->client_capabilities.supportsArgsCanBeInterpretedByShell = cJSON_IsTrue(supports_args_shell);
        }
        
        cJSON *supports_start_debugging = cJSON_GetObjectItem(args, "supportsStartDebuggingRequest");
        if (supports_start_debugging && cJSON_IsBool(supports_start_debugging)) {
            server->client_capabilities.supportsStartDebuggingRequest = cJSON_IsTrue(supports_start_debugging);
        }

        // Log the client information
        DAP_SERVER_DEBUG_LOG("Initialized with client: %s (%s)", 
            server->client_capabilities.clientName ? server->client_capabilities.clientName : "unknown",
            server->client_capabilities.clientID ? server->client_capabilities.clientID : "unknown");
    }

    // Create the response with our capabilities
    cJSON *capabilities = cJSON_CreateObject();
    if (!capabilities)
    {
        set_response_error(response, "Failed to create capabilities object");
        return -1;
    }

    // Add supported capabilities to the response
    for (int i = 0; i < DAP_CAP_COUNT; i++) {         
        cJSON_AddBoolToObject(capabilities, server_capabilities[i].name, server_capabilities[i].supported);        
    }

    // Create and add exception filters
    cJSON *exceptionFilters = cJSON_CreateArray();
    if (exceptionFilters)
    {
        // Add all defined exception filters
        for (int i = 0; i < DAP_EXC_FILTER_COUNT; i++) {
            cJSON *filter = cJSON_CreateObject();
            if (filter) {
                cJSON_AddStringToObject(filter, "filter", exception_filters[i].id);
                cJSON_AddStringToObject(filter, "label", exception_filters[i].label);
                cJSON_AddStringToObject(filter, "description", exception_filters[i].description);
                cJSON_AddBoolToObject(filter, "default", exception_filters[i].default_value);
                cJSON_AddItemToArray(exceptionFilters, filter);
            }
        }

        cJSON_AddItemToObject(capabilities, "exceptionBreakpointFilters", exceptionFilters);
    }

    // Set ANSI styling if client supports it
    if (server->client_capabilities.supportsANSIStyling) {
        cJSON_AddBoolToObject(capabilities, "supportsANSIStyling", true);
    }

    set_response_success(response, capabilities);
    // cJSON_Delete(capabilities); -- No longer needed, set_response_success will free it
    
    // Mark that we've received initialize
    server->is_initialized = true;
    
    // Note: The 'initialized' event will be sent by dap_server_handle_request
    // immediately after sending this response, as per the DAP specification
    
    return 0;
}

/**
 * @brief Handle execution control commands (continue, step, etc.)
 *
 * This function is currently unused but kept for future execution control implementation.
 * It will be used to centralize the handling of all execution control commands
 * and provide consistent behavior across different execution modes.
 */
int handle_execution_control(DAPServer *server, DAPCommandType command, cJSON *args, DAPResponse *response)
{
    if (!server->is_running || !server->attached)
    {
        set_response_error(response, "Debugger is not running or not attached");
        return -1;
    }

    // Parse thread ID and single_thread flag
    int thread_id = 1; // Default to thread 1
    bool single_thread = false;

    if (args)
    {
        cJSON *thread_id_json = cJSON_GetObjectItem(args, "threadId");
        if (thread_id_json && cJSON_IsNumber(thread_id_json))
        {
            thread_id = thread_id_json->valueint;
        }

        cJSON *single_thread_json = cJSON_GetObjectItem(args, "singleThread");
        if (single_thread_json && cJSON_IsBool(single_thread_json))
        {
            single_thread = cJSON_IsTrue(single_thread_json);
        }
    }

    // Validate thread ID
    if (thread_id != 1)
    {
        set_response_error(response, "Invalid thread ID - only thread 1 is supported");
        return -1;
    }

    // Handle different commands
    switch (command)
    {
    case DAP_CMD_PAUSE:
        if (!server->debugger_state.has_stopped)
        {
            server->debugger_state.has_stopped = true;
            // If single_thread is true, only pause the specified thread
            if (single_thread && thread_id != server->debugger_state.current_thread_id)
            {
                set_response_error(response, "Cannot pause non-current thread in single-thread mode");
                return -1;
            }

            // Create success response with thread information
            cJSON *body = cJSON_CreateObject();
            if (!body)
            {
                set_response_error(response, "Failed to create response body");
                return -1;
            }

            cJSON_AddNumberToObject(body, "threadId", thread_id);
            cJSON_AddStringToObject(body, "reason", "pause");
            cJSON_AddBoolToObject(body, "allThreadsStopped", true);

            set_response_success(response, body);
            // body is freed by set_response_success
            return 0;
        }
        set_response_error(response, "Debugger is already paused");
        return -1;

    case DAP_CMD_CONTINUE:
    case DAP_CMD_NEXT:
    case DAP_CMD_STEP_IN:
    case DAP_CMD_STEP_OUT:
        if (server->debugger_state.has_stopped)
        {
            // If single_thread is true, only continue the specified thread
            if (single_thread && thread_id != server->debugger_state.current_thread_id)
            {
                set_response_error(response, "Cannot continue non-current thread in single-thread mode");
                return -1;
            }
            server->debugger_state.has_stopped = false;
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

int handle_set_breakpoints(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!args || !response) {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    // Set command type
    server->current_command.type = DAP_CMD_SET_BREAKPOINTS;
    memset(&server->current_command.context.breakpoint, 0, sizeof(BreakpointCommandContext));
    
    // Parse source
    cJSON *source = cJSON_GetObjectItem(args, "source");
    if (!source) {
        set_response_error(response, "Missing source");
        return -1;
    }
    
    // Get source path and name
    cJSON *path = cJSON_GetObjectItem(source, "path");
    if (path && cJSON_IsString(path)) {
        server->current_command.context.breakpoint.source_path = strdup(path->valuestring);
    } else {
        set_response_error(response, "Missing source path");
        return -1;
    }
    
    cJSON *name = cJSON_GetObjectItem(source, "name");
    if (name && cJSON_IsString(name)) {
        server->current_command.context.breakpoint.source_name = strdup(name->valuestring);
    }
    
    // Check for sourceModified flag
    cJSON *source_modified = cJSON_GetObjectItem(args, "sourceModified");
    if (source_modified && cJSON_IsBool(source_modified)) {
        server->current_command.context.breakpoint.source_modified = cJSON_IsTrue(source_modified);
    }
    
    // Parse breakpoints array
    cJSON *breakpoints = cJSON_GetObjectItem(args, "breakpoints");
    DAPBreakpoint *bp_array = NULL;
    int count = 0;
    
    if (breakpoints && cJSON_IsArray(breakpoints)) {
        count = cJSON_GetArraySize(breakpoints);
        if (count > 0) {
            // Allocate array of DAPBreakpoint objects
            bp_array = malloc(count * sizeof(DAPBreakpoint));
            if (!bp_array) {
                cleanup_command_context(server);
                set_response_error(response, "Memory allocation failed");
                return -1;
            }
            
            // Parse each breakpoint
            for (int i = 0; i < count; i++) {
                cJSON *bp = cJSON_GetArrayItem(breakpoints, i);
                if (!bp) continue;
                
                memset(&bp_array[i], 0, sizeof(DAPBreakpoint));
                
                // Required: line
                cJSON *line = cJSON_GetObjectItem(bp, "line");
                if (line && cJSON_IsNumber(line)) {
                    bp_array[i].line = line->valueint;
                }
                
                // Optional: column
                cJSON *column = cJSON_GetObjectItem(bp, "column");
                if (column && cJSON_IsNumber(column)) {
                    bp_array[i].column = column->valueint;
                }
                
                // Optional: condition
                cJSON *condition = cJSON_GetObjectItem(bp, "condition");
                if (condition && cJSON_IsString(condition)) {
                    bp_array[i].condition = strdup(condition->valuestring);
                }
                
                // Optional: hitCondition
                cJSON *hit_condition = cJSON_GetObjectItem(bp, "hitCondition");
                if (hit_condition && cJSON_IsString(hit_condition)) {
                    bp_array[i].hit_condition = strdup(hit_condition->valuestring);
                }
                
                // Optional: logMessage
                cJSON *log_message = cJSON_GetObjectItem(bp, "logMessage");
                if (log_message && cJSON_IsString(log_message)) {
                    bp_array[i].log_message = strdup(log_message->valuestring);
                }
                
                // Set default verified state
                bp_array[i].verified = true;
                
                // Create source ref for each breakpoint
                bp_array[i].source = malloc(sizeof(DAPSource));
                if (bp_array[i].source) {
                    memset(bp_array[i].source, 0, sizeof(DAPSource));
                    
                    if (server->current_command.context.breakpoint.source_path) {
                        ((DAPSource*)bp_array[i].source)->path = 
                            strdup(server->current_command.context.breakpoint.source_path);
                    }
                    
                    if (server->current_command.context.breakpoint.source_name) {
                        ((DAPSource*)bp_array[i].source)->name = 
                            strdup(server->current_command.context.breakpoint.source_name);
                    }
                }
            }
            
            // Store the breakpoints in the command context
            server->current_command.context.breakpoint.breakpoints = bp_array;
            server->current_command.context.breakpoint.breakpoint_count = count;
        }
    } else {
        // DAP spec allows this - it means clear all breakpoints for this source
        server->current_command.context.breakpoint.breakpoints = NULL;
        server->current_command.context.breakpoint.breakpoint_count = 0;
    }
    
    // Call implementation callback
    int result = 0;
    const DAPBreakpoint *result_breakpoints = server->current_command.context.breakpoint.breakpoints;
    int result_count = server->current_command.context.breakpoint.breakpoint_count;
    
    if (server->command_callbacks[DAP_CMD_SET_BREAKPOINTS]) {
        DAP_SERVER_DEBUG_LOG("Calling implementation callback for setBreakpoints");
        
        // Call the implementation - it will read from the context but not free anything
        result = server->command_callbacks[DAP_CMD_SET_BREAKPOINTS](server);
        
        // Note: The callback may change the breakpoint information for the response,
        // but it does NOT take ownership of any memory allocated here
    } else {
        DAP_SERVER_DEBUG_LOG("No implementation callback for setBreakpoints");
    }
    
    // Create response from context after callback
    cJSON *body = cJSON_CreateObject();
    if (!body) {
        // Free the breakpoints we allocated
        free_breakpoints_array(bp_array, count);
        
        cleanup_command_context(server);
        set_response_error(response, "Failed to create response body");
        return -1;
    }
    
    // Create breakpoints array for response
    cJSON *response_breakpoints = cJSON_CreateArray();
    if (!response_breakpoints) {
        cJSON_Delete(body);
        
        // Free the breakpoints we allocated
        free_breakpoints_array(bp_array, count);
        
        cleanup_command_context(server);
        set_response_error(response, "Failed to create breakpoints array");
        return -1;
    }
    
    // Add each breakpoint to response (using the possibly updated values from the callback)
    for (int i = 0; i < result_count; i++) {
        const DAPBreakpoint *bp = &result_breakpoints[i];
        
        cJSON *response_bp = cJSON_CreateObject();
        if (!response_bp) continue;
        
        // Required fields
        cJSON_AddNumberToObject(response_bp, "id", i + 1);
        cJSON_AddBoolToObject(response_bp, "verified", bp->verified);
        cJSON_AddNumberToObject(response_bp, "line", bp->line);
        
        // Optional fields
        if (bp->column > 0) {
            cJSON_AddNumberToObject(response_bp, "column", bp->column);
        }
        
        if (bp->message) {
            cJSON_AddStringToObject(response_bp, "message", bp->message);
        }
        
        // Add source information
        if (bp->source) {
            cJSON *source_obj = cJSON_CreateObject();
            if (source_obj) {
                if (bp->source->path) {
                    cJSON_AddStringToObject(source_obj, "path", bp->source->path);
                }
                
                if (bp->source->name) {
                    cJSON_AddStringToObject(source_obj, "name", bp->source->name);
                }
                
                cJSON_AddItemToObject(response_bp, "source", source_obj);
            }
        }
        
        cJSON_AddItemToArray(response_breakpoints, response_bp);
    }
    
    cJSON_AddItemToObject(body, "breakpoints", response_breakpoints);
    set_response_success(response, body);
    
    // Always free the breakpoints array we allocated
    if (bp_array) {
        free_breakpoints_array(bp_array, count);
        // Clear the pointer to avoid double-free in cleanup_command_context
        if (server->current_command.context.breakpoint.breakpoints == bp_array) {
            server->current_command.context.breakpoint.breakpoints = NULL;
        }
    }
    
    // Clean up command context (will free the source paths)
    cleanup_command_context(server);
    
    return result;
}

/**
 * @brief Helper function to free a breakpoints array and all its contents
 * 
 * @param breakpoints Array of breakpoints to free
 * @param count Number of breakpoints in the array
 */
void free_breakpoints_array(const DAPBreakpoint *breakpoints, int count) {
    if (!breakpoints || count <= 0) {
        return;
    }
    
    for (int i = 0; i < count; i++) {
        // Free any condition strings
        if (breakpoints[i].condition) {
            free((void*)breakpoints[i].condition);
        }
        
        if (breakpoints[i].hit_condition) {
            free((void*)breakpoints[i].hit_condition);
        }
        
        if (breakpoints[i].log_message) {
            free((void*)breakpoints[i].log_message);
        }
        
        if (breakpoints[i].message) {
            free((void*)breakpoints[i].message);
        }
        
        // Free the source object and its members
        if (breakpoints[i].source) {
            if (breakpoints[i].source->path) {
                free((void*)breakpoints[i].source->path);
            }
            
            if (breakpoints[i].source->name) {
                free((void*)breakpoints[i].source->name);
            }
            
            free((void*)breakpoints[i].source);
        }
    }
    
    // Free the breakpoints array
    free((void*)breakpoints);
}

/**
 * @brief Handle disassemble command
 *
 * @param args Command arguments
 * @param response Response structure to fill
 * @return int 0 on success, non-zero on failure
 */
int handle_disassemble(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server || !args || !response)
    {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    // Initialize the command context for disassemble
    server->current_command.type = DAP_CMD_DISASSEMBLE;
    memset(&server->current_command.context.disassemble, 0, sizeof(DisassembleCommandContext));

    // Parse required arguments - memoryReference
    cJSON *memory_reference = cJSON_GetObjectItem(args, "memoryReference");
    if (!memory_reference || !cJSON_IsString(memory_reference))
    {
        set_response_error(response, "Missing or invalid memoryReference");
        return -1;
    }
    
    // Store memory reference in context
    server->current_command.context.disassemble.memory_reference = strdup(memory_reference->valuestring);
    if (!server->current_command.context.disassemble.memory_reference) {
        set_response_error(response, "Failed to allocate memory for memoryReference");
        return -1;
    }

    // Parse optional arguments with defaults
    cJSON *offset_json = cJSON_GetObjectItem(args, "offset");
    if (offset_json && cJSON_IsNumber(offset_json))
    {
        server->current_command.context.disassemble.offset = (uint64_t)offset_json->valuedouble;
    }

    cJSON *instruction_offset_json = cJSON_GetObjectItem(args, "instructionOffset");
    if (instruction_offset_json && cJSON_IsNumber(instruction_offset_json))
    {
        server->current_command.context.disassemble.instruction_offset = instruction_offset_json->valueint;
    }

    // Default to 10 instructions if not specified
    server->current_command.context.disassemble.instruction_count = 10;
    cJSON *instruction_count_json = cJSON_GetObjectItem(args, "instructionCount");
    if (instruction_count_json && cJSON_IsNumber(instruction_count_json))
    {
        server->current_command.context.disassemble.instruction_count = instruction_count_json->valueint;
    }

    cJSON *resolve_symbols_json = cJSON_GetObjectItem(args, "resolveSymbols");
    if (resolve_symbols_json && cJSON_IsBool(resolve_symbols_json))
    {
        server->current_command.context.disassemble.resolve_symbols = cJSON_IsTrue(resolve_symbols_json);
    }

    // Call the implementation callback if registered
    if (server->command_callbacks[DAP_CMD_DISASSEMBLE]) {
        DAP_SERVER_DEBUG_LOG("Calling implementation callback for disassemble");
        
        int callback_result = server->command_callbacks[DAP_CMD_DISASSEMBLE](server);
        if (callback_result < 0) {
            DAP_SERVER_DEBUG_LOG("Disassemble implementation callback failed");
            set_response_error(response, "Disassemble implementation callback failed");
            return -1;
        }
        
        // The callback should have prepared the disassembly data for the response
        // We just need to set success=true and return
        response->success = true;
        return 0;
    }
    
    DAP_SERVER_DEBUG_LOG("No implementation callback for disassemble, using default implementation");

    // Default implementation if no callback is registered
    // Convert memory reference to address
    char *endptr = NULL;
    uint32_t address = (uint32_t)strtoul(server->current_command.context.disassemble.memory_reference, &endptr, 0);
    if (endptr == server->current_command.context.disassemble.memory_reference || *endptr != '\0')
    {
        set_response_error(response, "Invalid memory reference format");
        return -1;
    }

    // Apply offset to address
    address += (uint32_t)server->current_command.context.disassemble.offset;

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    cJSON *instructions = cJSON_CreateArray();
    if (!instructions)
    {
        cJSON_Delete(body);
        set_response_error(response, "Failed to create instructions array");
        return -1;
    }

    // Calculate total instructions to disassemble
    int instruction_offset = server->current_command.context.disassemble.instruction_offset;
    int instruction_count = server->current_command.context.disassemble.instruction_count;
    size_t total_instructions = instruction_count + (instruction_offset > 0 ? instruction_offset : 0);

    // Allocate array for disassembly strings
    char **disassembly = malloc(total_instructions * sizeof(char *));
    if (!disassembly)
    {
        cJSON_Delete(body);
        cJSON_Delete(instructions);
        set_response_error(response, "Failed to allocate memory for disassembly");
        return -1;
    }

    // Mock disassembly - in a real implementation, this would use the machine debugger
    for (size_t i = 0; i < total_instructions; i++)
    {
        char *instr = malloc(32);
        if (!instr)
        {
            // Clean up previously allocated strings
            for (size_t j = 0; j < i; j++)
            {
                free(disassembly[j]);
            }
            free(disassembly);
            cJSON_Delete(body);
            cJSON_Delete(instructions);
            set_response_error(response, "Failed to allocate memory for instruction");
            return -1;
        }
        snprintf(instr, 32, "MOV R%d, R%d", (int)(i % 8), (int)((i + 1) % 8));
        disassembly[i] = instr;
    }

    // Add instructions to response
    for (size_t i = 0; i < (size_t)instruction_count; i++)
    {
        size_t idx = i;
        if (instruction_offset > 0) {
            idx += instruction_offset;
        }
        
        if (idx >= total_instructions || !disassembly[idx])
        {
            break;
        }

        cJSON *instruction = cJSON_CreateObject();
        if (!instruction)
        {
            // Clean up and return error
            for (size_t j = 0; j < total_instructions; j++)
            {
                free(disassembly[j]);
            }
            free(disassembly);
            cJSON_Delete(body);
            cJSON_Delete(instructions);
            set_response_error(response, "Failed to create instruction object");
            return -1;
        }

        // Format address as hexadecimal
        char addr_str[16];
        snprintf(addr_str, sizeof(addr_str), "0x%04x", address + (uint32_t)(i * 4));
        cJSON_AddStringToObject(instruction, "address", addr_str);

        // Add instruction text
        cJSON_AddStringToObject(instruction, "instruction", disassembly[idx]);

        // If resolve_symbols is true, try to resolve symbol names
        if (server->current_command.context.disassemble.resolve_symbols)
        {
            // Mock symbol resolution
            cJSON_AddStringToObject(instruction, "symbol", "");
        }

        cJSON_AddItemToArray(instructions, instruction);
    }

    // Clean up disassembly strings
    for (size_t i = 0; i < total_instructions; i++)
    {
        free(disassembly[i]);
    }
    free(disassembly);

    // Add instructions array to body
    cJSON_AddItemToObject(body, "instructions", instructions);

    // Set response
    set_response_success(response, body);

    return 0;
}

int handle_continue(DAPServer *server, cJSON *args, DAPResponse *response)
{
    (void)args; // Mark as unused
    if (!server->is_running || !server->attached)
    {
        set_response_error(response, "Debugger not running or attached");
        return -1;
    }

    if (!server->debugger_state.has_stopped)
    {
        set_response_error(response, "Debugger not stopped");
        return -1;
    }

    // Create success response
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    cJSON_AddBoolToObject(body, "allThreadsContinued", true);

    set_response_success(response, body);
    // body is freed by set_response_success

    server->debugger_state.has_stopped = false;
    return 0;
}


int handleStepCommand(const char *command, DAPServer *server, cJSON *args, DAPResponse *response)
{
    DAPCommandType cmd_type = DAP_CMD_INVALID;
    DAPCommandCallback callback = NULL;
    
    // Default string to use for statement granularity - never free this
    static const char* STATEMENT_GRANULARITY = "statement";

    // Determine which command type we're handling
    if (strcmp(command, "next") == 0) {
        cmd_type = DAP_CMD_NEXT;
        callback = server->command_callbacks[DAP_CMD_NEXT];
    } else if (strcmp(command, "stepIn") == 0) {
        cmd_type = DAP_CMD_STEP_IN;
        callback = server->command_callbacks[DAP_CMD_STEP_IN];
    } else if (strcmp(command, "stepOut") == 0) {
        cmd_type = DAP_CMD_STEP_OUT;
        callback = server->command_callbacks[DAP_CMD_STEP_OUT];
    }

    if (!callback) {
        DAP_SERVER_DEBUG_LOG("No callback registered for %s", command);
        set_response_error(response, "No callback registered");
        return -1;
    }

    if (!server->is_running || !server->attached) {
        set_response_error(response, "Debugger not running or attached");
        return -1;
    }

    if (!server->debugger_state.has_stopped) {
        set_response_error(response, "Debugger not stopped");
        return -1;
    }

    // Parse arguments and populate command context
    server->current_command.type = cmd_type;
    memset(&server->current_command.context.step, 0, sizeof(StepCommandContext));
    
    // Set defaults
    server->current_command.context.step.thread_id = 1;  // Default to thread 1
    server->current_command.context.step.single_thread = false;
    server->current_command.context.step.granularity = STATEMENT_GRANULARITY;  // Use static string literal
    server->current_command.context.step.target_id = -1;  // Not used for step next
    
    // Extract thread_id
    cJSON *thread_id_json = cJSON_GetObjectItem(args, "threadId");
    if (thread_id_json && cJSON_IsNumber(thread_id_json)) {
        server->current_command.context.step.thread_id = thread_id_json->valueint;
    }

    // Extract singleThread flag
    cJSON *single_thread_json = cJSON_GetObjectItem(args, "singleThread");
    if (single_thread_json && cJSON_IsBool(single_thread_json)) {
        server->current_command.context.step.single_thread = cJSON_IsTrue(single_thread_json);
    }
    
    // Extract granularity if available
    cJSON *granularity_json = cJSON_GetObjectItem(args, "granularity");
    if (granularity_json && cJSON_IsString(granularity_json)) {
        // Make a copy of the string as we own this memory
        server->current_command.context.step.granularity = strdup(granularity_json->valuestring);
        if (!server->current_command.context.step.granularity) {
            // If memory allocation fails, fallback to default
            server->current_command.context.step.granularity = STATEMENT_GRANULARITY;
        }
    }
    
    // Extract targetId for stepIn if provided
    if (cmd_type == DAP_CMD_STEP_IN) {
        cJSON *target_id_json = cJSON_GetObjectItem(args, "targetId");
        if (target_id_json && cJSON_IsNumber(target_id_json)) {
            server->current_command.context.step.target_id = target_id_json->valueint;
        }
    }

    // Call the implementation callback
    DAP_SERVER_DEBUG_LOG("Calling implementation callback for %s", command);
    int callback_result = callback(server);
    
    if (callback_result < 0) {
        DAP_SERVER_DEBUG_LOG("Callback failed");
        
        // Clean up any memory we allocated
        // Only free if it's NOT our default static string
        if (granularity_json && server->current_command.context.step.granularity && 
            server->current_command.context.step.granularity != STATEMENT_GRANULARITY) {
            free((void*)server->current_command.context.step.granularity);
            server->current_command.context.step.granularity = STATEMENT_GRANULARITY;
        }
        
        set_response_error(response, "Step implementation callback failed");
        return -1;
    }

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body) {
        // Clean up any memory we allocated
        // Only free if it's NOT our default static string
        if (granularity_json && server->current_command.context.step.granularity && 
            server->current_command.context.step.granularity != STATEMENT_GRANULARITY) {
            free((void*)server->current_command.context.step.granularity);
            server->current_command.context.step.granularity = STATEMENT_GRANULARITY;
        }
        
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    cJSON_AddBoolToObject(body, "allThreadsStopped", !server->current_command.context.step.single_thread);
    
    // Set success response
    set_response_success(response, body);

    // Send the stopped event after successful step
    dap_server_send_stopped_event(server, "step", NULL);
    
    // Clean up any memory we allocated
    // Only free if it's NOT our default static string
    if (granularity_json && server->current_command.context.step.granularity && 
        server->current_command.context.step.granularity != STATEMENT_GRANULARITY) {
        free((void*)server->current_command.context.step.granularity);
        server->current_command.context.step.granularity = STATEMENT_GRANULARITY;
    }

    return 0;
}

int handle_next(DAPServer *server, cJSON *args, DAPResponse *response)
{

    return handleStepCommand("next", server, args, response);
}


int handle_step_in(DAPServer *server, cJSON *args, DAPResponse *response)
{

    return handleStepCommand("stepIn", server, args, response);

#if 0
    if (!server->is_running || !server->attached)
    {
        response->success = false;
        response->error_message = strdup("Debugger not running or attached");
        return 0;
    }

    if (!server->paused)
    {
        response->success = false;
        response->error_message = strdup("Debugger not paused");
        return 0;
    }

    // Parse arguments and populate command context
    memset(&server->current_command.context.step, 0, sizeof(StepCommandContext));
    server->current_command.context.step.thread_id = 1;  // Default to thread 1
    server->current_command.context.step.single_thread = false;
    server->current_command.context.step.granularity = "statement";  // Default granularity
    server->current_command.context.step.target_id = -1;  // No specific target

    // Extract thread_id
    cJSON *thread_id_json = cJSON_GetObjectItem(args, "threadId");
    if (thread_id_json && cJSON_IsNumber(thread_id_json))
    {
        server->current_command.context.step.thread_id = thread_id_json->valueint;
    }

    // Extract singleThread flag
    cJSON *single_thread_json = cJSON_GetObjectItem(args, "singleThread");
    if (single_thread_json && cJSON_IsBool(single_thread_json))
    {
        server->current_command.context.step.single_thread = cJSON_IsTrue(single_thread_json);
    }
    
    // Extract granularity if available
    cJSON *granularity_json = cJSON_GetObjectItem(args, "granularity");
    if (granularity_json && cJSON_IsString(granularity_json))
    {
        server->current_command.context.step.granularity = strdup(granularity_json->valuestring);
    }

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    // Validate thread ID
    if (server->current_command.context.step.thread_id < 0)
    {
        response->success = false;
        response->error_message = strdup("Invalid thread ID");
        return 0;
    }

    cJSON_AddBoolToObject(body, "allThreadsStopped", !server->current_command.context.step.single_thread);

    
    // Check if we have an implementation callback registered for this command
    if (server->command_callbacks[DAP_CMD_STEP_IN])
    {
        // Call the implementation callback
        DAP_SERVER_DEBUG_LOG("Calling implementation callback for stepOut");
        int callback_result = server->command_callbacks[DAP_CMD_STEP_OUT](server);

    

        if (callback_result < 0)
        {
            DAP_SERVER_DEBUG_LOG("StepOut implementation callback failed");
            set_response_error(response, "StepOut implementation callback failed");
            return -1;
        }

         // Set success response
        set_response_success(response, body);
    
    } else {
        DAP_SERVER_DEBUG_LOG("No stepOut callback registered");
        set_response_error(response, "No stepOut callback registered");
        return -1;
    }







    cJSON *event_body = cJSON_CreateObject();
    if (event_body)
    {
        cJSON_AddStringToObject(event_body, "reason", "step");
        cJSON_AddNumberToObject(event_body, "threadId", server->current_thread_id);
        cJSON_AddBoolToObject(event_body, "allThreadsStopped", !server->current_command.context.step.single_thread);
        cJSON_AddStringToObject(event_body, "description", "Stepped into instruction");

        if (server->current_source)
        {
            cJSON *source = cJSON_CreateObject();
            if (source)
            {
                cJSON_AddStringToObject(source, "name", server->current_source->name);
                cJSON_AddStringToObject(source, "path", server->current_source->path);
                cJSON_AddItemToObject(event_body, "source", source);
            }
        }

        // Add line information if available
        if (server->current_line > 0)
        {
            cJSON_AddNumberToObject(event_body, "line", server->current_line);
            cJSON_AddNumberToObject(event_body, "column", server->current_column);
        }

        dap_server_send_event(server, "stopped", event_body);
        // Remove this line as it causes a double-free - dap_server_send_event already handles freeing the body
        // cJSON_Delete(event_body);
    }

    return 0;
#endif
}

int handle_step_out(DAPServer *server, cJSON *args, DAPResponse *response)
{
    return handleStepCommand("stepOut", server, args, response);

#if 0  
    if (!server->is_running || !server->attached)
    {
        response->success = false;
        response->error_message = strdup("Debugger not running or attached");
        return 0;
    }

    if (!server->paused)
    {
        response->success = false;
        response->error_message = strdup("Debugger not paused");
        return 0;
    }

    // Parse arguments and populate command context
    memset(&server->current_command.context.step, 0, sizeof(StepCommandContext));
    server->current_command.context.step.thread_id = 1;  // Default to thread 1
    server->current_command.context.step.single_thread = false;
    server->current_command.context.step.granularity = "statement";  // Default granularity
    server->current_command.context.step.target_id = -1;  // No specific target
    
    // Extract thread_id
    cJSON *thread_id_json = cJSON_GetObjectItem(args, "threadId");
    if (thread_id_json && cJSON_IsNumber(thread_id_json))
    {
        server->current_command.context.step.thread_id = thread_id_json->valueint;
    }

    // Extract singleThread flag
    cJSON *single_thread_json = cJSON_GetObjectItem(args, "singleThread");
    if (single_thread_json && cJSON_IsBool(single_thread_json))
    {
        server->current_command.context.step.single_thread = cJSON_IsTrue(single_thread_json);
    }
    
    // Extract granularity if available
    cJSON *granularity_json = cJSON_GetObjectItem(args, "granularity");
    if (granularity_json && cJSON_IsString(granularity_json))
    {
        server->current_command.context.step.granularity = strdup(granularity_json->valuestring);
    }

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    cJSON_AddBoolToObject(body, "allThreadsStopped", !server->current_command.context.step.single_thread);

    
    // Check if we have an implementation callback registered for this command
    if (server->command_callbacks[DAP_CMD_STEP_OUT])
    {
        // Call the implementation callback
        DAP_SERVER_DEBUG_LOG("Calling implementation callback for stepOut");
        int callback_result = server->command_callbacks[DAP_CMD_STEP_OUT](server);

    

        if (callback_result < 0)
        {
            DAP_SERVER_DEBUG_LOG("StepOut implementation callback failed");
            set_response_error(response, "StepOut implementation callback failed");
            return -1;
        }

         // Set success response
        set_response_success(response, body);
    
    } else {
        DAP_SERVER_DEBUG_LOG("No stepOut callback registered");
        set_response_error(response, "No stepOut callback registered");
        return -1;
    }


    
    return 0;
#endif
}

int handle_read_memory(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server || !args || !response)
    {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    // Initialize the command context for readMemory
    server->current_command.type = DAP_CMD_READ_MEMORY;
    memset(&server->current_command.context.read_memory, 0, sizeof(ReadMemoryCommandContext));

    // Parse required arguments - memoryReference
    cJSON *memory_reference = cJSON_GetObjectItem(args, "memoryReference");
    if (!memory_reference || !cJSON_IsString(memory_reference))
    {
        set_response_error(response, "Missing or invalid memoryReference");
        return -1;
    }
    
    // Store memory reference in context
    server->current_command.context.read_memory.memory_reference = strdup(memory_reference->valuestring);
    if (!server->current_command.context.read_memory.memory_reference) {
        set_response_error(response, "Failed to allocate memory for memoryReference");
        return -1;
    }

    // Parse count parameter (required)
    cJSON *count_json = cJSON_GetObjectItem(args, "count");
    if (!count_json || !cJSON_IsNumber(count_json))
    {
        set_response_error(response, "Missing or invalid count parameter");
        return -1;
    }
    server->current_command.context.read_memory.count = (size_t)count_json->valueint;

    // Parse optional offset parameter (defaults to 0)
    server->current_command.context.read_memory.offset = 0;
    cJSON *offset_json = cJSON_GetObjectItem(args, "offset");
    if (offset_json && cJSON_IsNumber(offset_json))
    {
        server->current_command.context.read_memory.offset = (uint64_t)offset_json->valuedouble;
    }

    // Validate parameters
    if (server->current_command.context.read_memory.count <= 0 || 
        server->current_command.context.read_memory.count > 1024)
    {
        set_response_error(response, "Invalid count parameter (must be > 0 and <= 1024)");
        return -1;
    }

    // Call the implementation callback if registered
    if (server->command_callbacks[DAP_CMD_READ_MEMORY]) {
        DAP_SERVER_DEBUG_LOG("Calling implementation callback for readMemory");
        
        int callback_result = server->command_callbacks[DAP_CMD_READ_MEMORY](server);
        if (callback_result < 0) {
            DAP_SERVER_DEBUG_LOG("readMemory implementation callback failed");
            set_response_error(response, "readMemory implementation callback failed");
            return -1;
        }
        
        // The callback should have prepared the memory data for the response
        // We just need to set success=true and return
        response->success = true;
        return 0;
    }
    
    DAP_SERVER_DEBUG_LOG("No implementation callback for readMemory, using default implementation");

    // Default implementation if no callback is registered
    // This will be a mock implementation that returns dummy data
    char *endptr = NULL;
    uint32_t address = (uint32_t)strtoul(server->current_command.context.read_memory.memory_reference, &endptr, 0);
    if (endptr == server->current_command.context.read_memory.memory_reference || *endptr != '\0')
    {
        set_response_error(response, "Invalid memory reference format");
        return -1;
    }

    // Apply offset to address
    address += (uint32_t)server->current_command.context.read_memory.offset;

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Format address as a string (per DAP spec)
    char address_str[32];
    snprintf(address_str, sizeof(address_str), "0x%08x", address);
    cJSON_AddStringToObject(body, "address", address_str);
    
    // Create fake data - a repeating pattern based on the address
    size_t count = server->current_command.context.read_memory.count;
    uint8_t *data = malloc(count);
    if (!data) {
        cJSON_Delete(body);
        set_response_error(response, "Failed to allocate memory for data");
        return -1;
    }
    
    // Fill with a simple pattern
    for (size_t i = 0; i < count; i++) {
        data[i] = (uint8_t)((address + i) & 0xFF);
    }
    
    // Encode as base64
    char *encoded = base64_encode(data, count);
    free(data);
    
    if (!encoded) {
        cJSON_Delete(body);
        set_response_error(response, "Failed to encode data as base64");
        return -1;
    }
    
    cJSON_AddStringToObject(body, "data", encoded);
    free(encoded);
    
    // Add unreadableBytes = 0 (all bytes were readable)
    cJSON_AddNumberToObject(body, "unreadableBytes", 0);
    
    // Set success response
    set_response_success(response, body);
    
    return 0;
}

int handle_write_memory(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server || !args || !response)
    {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    // Initialize the command context for writeMemory
    server->current_command.type = DAP_CMD_WRITE_MEMORY;
    memset(&server->current_command.context.write_memory, 0, sizeof(WriteMemoryCommandContext));

    // Parse required arguments - memoryReference
    cJSON *memory_reference = cJSON_GetObjectItem(args, "memoryReference");
    if (!memory_reference || !cJSON_IsString(memory_reference))
    {
        set_response_error(response, "Missing or invalid memoryReference");
        return -1;
    }
    
    // Store memory reference in context
    server->current_command.context.write_memory.memory_reference = strdup(memory_reference->valuestring);
    if (!server->current_command.context.write_memory.memory_reference) {
        set_response_error(response, "Failed to allocate memory for memoryReference");
        return -1;
    }

    // Parse required arguments - data
    cJSON *data = cJSON_GetObjectItem(args, "data");
    if (!data || !cJSON_IsString(data))
    {
        set_response_error(response, "Missing or invalid data");
        return -1;
    }
    
    // Store data in context
    server->current_command.context.write_memory.data = strdup(data->valuestring);
    if (!server->current_command.context.write_memory.data) {
        set_response_error(response, "Failed to allocate memory for data");
        return -1;
    }

    // Parse optional offset parameter (defaults to 0)
    server->current_command.context.write_memory.offset = 0;
    cJSON *offset_json = cJSON_GetObjectItem(args, "offset");
    if (offset_json && cJSON_IsNumber(offset_json))
    {
        server->current_command.context.write_memory.offset = (uint64_t)offset_json->valuedouble;
    }

    // Parse optional allowPartial parameter (defaults to false)
    server->current_command.context.write_memory.allow_partial = false;
    cJSON *allow_partial_json = cJSON_GetObjectItem(args, "allowPartial");
    if (allow_partial_json && cJSON_IsBool(allow_partial_json))
    {
        server->current_command.context.write_memory.allow_partial = cJSON_IsTrue(allow_partial_json);
    }

    // Call the implementation callback if registered
    if (server->command_callbacks[DAP_CMD_WRITE_MEMORY]) {
        DAP_SERVER_DEBUG_LOG("Calling implementation callback for writeMemory");
        
        int callback_result = server->command_callbacks[DAP_CMD_WRITE_MEMORY](server);
        if (callback_result < 0) {
            DAP_SERVER_DEBUG_LOG("writeMemory implementation callback failed");
            set_response_error(response, "writeMemory implementation callback failed");
            return -1;
        }
        
        // The callback should have prepared the response
        response->success = true;
        return 0;
    }
    
    DAP_SERVER_DEBUG_LOG("No implementation callback for writeMemory");
    set_response_error(response, "writeMemory not implemented");
    return -1;
}

int handle_read_registers(DAPServer *server, cJSON *args, DAPResponse *response)
{
    (void)args; // Mark as unused
    if (!server->is_running || !server->attached)
    {
        response->success = false;
        response->error_message = strdup("Debugger not running or attached");
        return 0;
    }

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    // Create registers array
    cJSON *registers = cJSON_CreateArray();
    if (!registers)
    {
        cJSON_Delete(body);
        response->success = false;
        response->error_message = strdup("Failed to create registers array");
        return 0;
    }

    // Add CPU registers
    for (size_t i = 0; i < NUM_REGISTERS; i++)
    {
        cJSON *reg = cJSON_CreateObject();
        if (!reg)
        {
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
        if (cpu_registers[i].has_nested)
        {
            cJSON_AddNumberToObject(reg, "variablesReference", cpu_registers[i].nested_ref);
        }
        cJSON_AddItemToArray(registers, reg);
    }

    cJSON_AddItemToObject(body, "registers", registers);

    // Convert to string
    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str)
    {
        response->success = false;
        response->error_message = strdup("Failed to format response body");
        return 0;
    }

    response->success = true;
    response->data = body_str;
    return 0;
}

int handle_write_register(DAPServer *server, cJSON *args, DAPResponse *response)
{
    (void)args; // Mark as unused
    if (!server->is_running || !server->attached)
    {
        response->success = false;
        response->error_message = strdup("Debugger not running or attached");
        return 0;
    }

    // Get register write parameters
    cJSON *name_json = cJSON_GetObjectItem(args, "name");
    cJSON *value_json = cJSON_GetObjectItem(args, "value");
    if (!name_json || !value_json)
    {
        response->success = false;
        response->error_message = strdup("Missing required parameters");
        return 0;
    }

    const char *name = name_json->valuestring;
    const char *value = value_json->valuestring;

    // Find register in CPU registers
    int reg_index = -1;
    for (size_t i = 0; i < NUM_REGISTERS; i++)
    {
        if (strcmp(name, cpu_registers[i].name) == 0)
        {
            reg_index = i;
            break;
        }
    }

    if (reg_index == -1)
    {
        response->success = false;
        response->error_message = strdup("Invalid register name");
        return 0;
    }

    // Parse value based on register type
    uint16_t reg_value;
    if (strcmp(cpu_registers[reg_index].type, "octal") == 0)
    {
        if (sscanf(value, "%ho", &reg_value) != 1)
        {
            response->success = false;
            response->error_message = strdup("Invalid octal value");
            return 0;
        }
    }
    else
    {
        if (sscanf(value, "0x%hx", &reg_value) != 1)
        {
            response->success = false;
            response->error_message = strdup("Invalid hex value");
            return 0;
        }
    }

    // Update register
    cpu_registers[reg_index].value = reg_value;

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    // Convert to string
    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str)
    {
        response->success = false;
        response->error_message = strdup("Failed to format response body");
        return 0;
    }

    response->success = true;
    response->data = body_str;
    return 0;
}

int handle_pause(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server->is_running || !server->attached)
    {
        response->success = false;
        response->error_message = strdup("Debugger not running or attached");
        return 0;
    }

    if (server->debugger_state.has_stopped)
    {
        response->success = false;
        response->error_message = strdup("Debugger already paused");
        return 0;
    }

    // Parse arguments
    int thread_id = -1;
    cJSON *thread_id_json = cJSON_GetObjectItem(args, "threadId");
    if (thread_id_json && cJSON_IsNumber(thread_id_json))
    {
        thread_id = thread_id_json->valueint;
    }

    // Validate thread ID
    if (thread_id < 0)
    {
        response->success = false;
        response->error_message = strdup("Invalid thread ID");
        return 0;
    }

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    cJSON_AddBoolToObject(body, "allThreadsStopped", true);

    // Convert to string
    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str)
    {
        response->success = false;
        response->error_message = strdup("Failed to format response body");
        return 0;
    }

    // Update debugger state
    server->debugger_state.has_stopped = true;
    server->debugger_state.current_thread_id = thread_id;

    response->success = true;
    response->data = body_str;

    // Send stopped event according to DAP spec

    cJSON *event_body = cJSON_CreateObject();
    if (event_body)
    {
        cJSON_AddStringToObject(event_body, "reason", "pause");
        cJSON_AddNumberToObject(event_body, "threadId", thread_id);
        cJSON_AddBoolToObject(event_body, "allThreadsStopped", true);
        cJSON_AddStringToObject(event_body, "description", "Thread paused by user");

        if (server->current_source)
        {
            cJSON *source = cJSON_CreateObject();
            if (source)
            {
                cJSON_AddStringToObject(source, "name", server->current_source->name);
                cJSON_AddStringToObject(source, "path", server->current_source->path);
                cJSON_AddItemToObject(event_body, "source", source);
            }
        }

        // Add line information if available
        if (server->debugger_state.source_line > 0)
        {
            cJSON_AddNumberToObject(event_body, "line", server->debugger_state.source_line);
            cJSON_AddNumberToObject(event_body, "column", server->debugger_state.source_column);
        }

        dap_server_send_event(server, "stopped", event_body);
        // Remove this line as it causes a double-free - dap_server_send_event already handles freeing the body
        // cJSON_Delete(event_body);
    }

    return 0;
}

// Implement missing handler functions
int handle_configuration_done(DAPServer *server, cJSON *args, DAPResponse *response)
{
    (void)server; // Mark as unused
    (void)args;   // Mark as unused

    if (!response)
        return -1;
    response->success = true;
    response->data = strdup("{}");
    return 0;
}

/**
 * @brief Evaluate an expression in the current context
 *
 * @param args JSON arguments containing the expression to evaluate
 * @param response Response to fill with results
 * @return int 0 on success, error code on failure
 */
int handle_evaluate(DAPServer *server, cJSON *args, DAPResponse *response)
{
    (void)server; // Mark as unused
    if (!args || !response)
        return -1;

    // Extract the expression from arguments
    cJSON *expression = cJSON_GetObjectItem(args, "expression");
    if (!expression || !cJSON_IsString(expression))
    {
        set_response_error(response, "Missing or invalid expression");
        return 0;
    }

    // For mock server, just echo back the expression with a mock evaluation
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return 0;
    }

    // In a real implementation, this would actually evaluate the expression
    cJSON_AddStringToObject(body, "result", expression->valuestring);
    cJSON_AddStringToObject(body, "type", "string");
    cJSON_AddNumberToObject(body, "variablesReference", 0);

    set_response_success(response, body);
    // body is freed by set_response_success
    return 0;
}

/**
 * @brief Return a list of loaded source files
 *
 * @param args JSON arguments (not used in this implementation)
 * @param response Response to fill with loaded sources
 * @return int 0 on success, error code on failure
 */
int handle_loaded_sources(DAPServer *server, cJSON *args, DAPResponse *response)
{
    (void)args; // Mark as unused
    if (!response)
        return -1;

    // Create mock response with current source file
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return 0;
    }

    cJSON *sources = cJSON_CreateArray();
    if (!sources)
    {
        cJSON_Delete(body);
        set_response_error(response, "Failed to create sources array");
        return 0;
    }

    // Add current source if available
    if (server->current_source)
    {
        cJSON *source = cJSON_CreateObject();
        if (source)
        {
            cJSON_AddStringToObject(source, "name", server->current_source->name);
            cJSON_AddStringToObject(source, "path", server->current_source->path);
            cJSON_AddNumberToObject(source, "sourceReference", 0);
            cJSON_AddItemToArray(sources, source);
        }
    }

    cJSON_AddItemToObject(body, "sources", sources);
    set_response_success(response, body);
    // body is freed by set_response_success
    return 0;
}

// static int handle_set_variable(cJSON* args, DAPResponse* response) { ... }
// static int handle_set_expression(cJSON* args, DAPResponse* response) { ... }
// static int handle_modules(cJSON* args, DAPResponse* response) { ... }
// static int handle_step_back(cJSON* args, DAPResponse* response) { ... }
// static int handle_set_instruction_breakpoints(cJSON* args, DAPResponse* response) { ... }
// static int handle_set_data_breakpoints(cJSON* args, DAPResponse* response) { ... }
// static int handle_exception_info(cJSON* args, DAPResponse* response) { ... }

int handle_launch(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server || !args || !response)
    {
        set_response_error(response, "Missing required parameters");
        return -1;
    }
    
    // Mark that we're handling a launch command
    server->current_command.type = DAP_CMD_LAUNCH;
    
    // Clear any previous state values that might be leftover
    if (server->debugger_state.program_path) {
        free((void*)server->debugger_state.program_path);
        server->debugger_state.program_path = NULL;
    }
    
    if (server->debugger_state.source_path) {
        free((void*)server->debugger_state.source_path);
        server->debugger_state.source_path = NULL;
    }
    
    if (server->debugger_state.map_path) {
        free((void*)server->debugger_state.map_path);
        server->debugger_state.map_path = NULL;
    }
    
    if (server->debugger_state.working_directory) {
        free((void*)server->debugger_state.working_directory);
        server->debugger_state.working_directory = NULL;
    }
    
    // Free any previous command line arguments
    if (server->debugger_state.args) {
        for (int i = 0; i < server->debugger_state.args_count; i++) {
            free(server->debugger_state.args[i]);
        }
        free(server->debugger_state.args);
        server->debugger_state.args = NULL;
        server->debugger_state.args_count = 0;
    }

    // Parse required field: program (executable path)
    cJSON *program_json = cJSON_GetObjectItem(args, "program");
    if (!program_json || !cJSON_IsString(program_json))
    {
        set_response_error(response, "Missing or invalid program path");
        return -1;
    }
    
    // Required field - program path
    const char* value_str = program_json->valuestring;
    if (!value_str) {
        set_response_error(response, "Program path is null");
        return -1;
    }
    
    char *program_path = strdup(value_str);
    if (!program_path) {
        set_response_error(response, "Failed to allocate memory for program path");
        return -1;
    }
    server->debugger_state.program_path = program_path;
    DAP_SERVER_DEBUG_LOG("Launch program path: %s", program_path);
    
    // Optional field - source file (default code file to display)
    cJSON *source_file_json = cJSON_GetObjectItem(args, "sourceFile");
    if (source_file_json && cJSON_IsString(source_file_json) && source_file_json->valuestring) {
        const char* source_str = source_file_json->valuestring;
        char *source_path = strdup(source_str);
        if (!source_path) {
            set_response_error(response, "Failed to allocate memory for source path");
            goto cleanup;
        }
        server->debugger_state.source_path = source_path;
        DAP_SERVER_DEBUG_LOG("Source file: %s", source_path);
    } else {
        // Make sure the source_path field is NULL to avoid dangling pointers
        server->debugger_state.source_path = NULL;
        DAP_SERVER_DEBUG_LOG("Source file: (not specified)");
    }
    
    // Optional field - map file (for address to source mapping)
    cJSON *map_file_json = cJSON_GetObjectItem(args, "mapFile");
    if (map_file_json && cJSON_IsString(map_file_json) && map_file_json->valuestring) {
        const char* map_str = map_file_json->valuestring;
        char *map_path = strdup(map_str);
        if (!map_path) {
            set_response_error(response, "Failed to allocate memory for map file path");
            goto cleanup;
        }
        server->debugger_state.map_path = map_path;
        DAP_SERVER_DEBUG_LOG("Map file: %s", map_path);
    } else {
        // Make sure the map_path field is NULL to avoid dangling pointers
        server->debugger_state.map_path = NULL;
        DAP_SERVER_DEBUG_LOG("Map file: (not specified)");
    }
    
    // Optional field - working directory
    cJSON *cwd_json = cJSON_GetObjectItem(args, "cwd");
    if (cwd_json && cJSON_IsString(cwd_json) && cwd_json->valuestring) {
        const char* cwd_str = cwd_json->valuestring;
        char *working_directory = strdup(cwd_str);
        if (!working_directory) {
            set_response_error(response, "Failed to allocate memory for working directory");
            goto cleanup;
        }
        server->debugger_state.working_directory = working_directory;
        DAP_SERVER_DEBUG_LOG("Working directory: %s", working_directory);
        
        // Change directory if specified (this could be moved to the implementation callback)
        if (chdir(cwd_str) != 0) {
            DAP_SERVER_DEBUG_LOG("Failed to change working directory: %s", strerror(errno));
            // Continue despite failure - the implementation can handle this
        }
    } else {
        // Make sure the working_directory field is NULL to avoid dangling pointers
        server->current_command.context.launch.working_directory = NULL;
        DAP_SERVER_DEBUG_LOG("Working directory: (not specified)");
    }
    
    // Optional field - noDebug flag
    cJSON *no_debug_json = cJSON_GetObjectItem(args, "noDebug");
    if (no_debug_json && cJSON_IsBool(no_debug_json)) {
        server->debugger_state.no_debug = cJSON_IsTrue(no_debug_json);
        DAP_SERVER_DEBUG_LOG("noDebug: %s", server->debugger_state.no_debug ? "true" : "false");
    }
    
    // Optional field - stopOnEntry flag
    cJSON *stop_entry_json = cJSON_GetObjectItem(args, "stopOnEntry");
    if (stop_entry_json && cJSON_IsBool(stop_entry_json)) {
        server->debugger_state.stop_at_entry = cJSON_IsTrue(stop_entry_json);
        DAP_SERVER_DEBUG_LOG("stopOnEntry: %s", server->debugger_state.stop_at_entry ? "true" : "false");
    }
    
    // Optional field - args (command line arguments)
    cJSON *args_json = cJSON_GetObjectItem(args, "args");
    if (args_json && cJSON_IsArray(args_json)) {
        int args_count = cJSON_GetArraySize(args_json);
        if (args_count > 0) {
            // Allocate array of char* pointers
            char **cmd_args = calloc(args_count + 1, sizeof(char*)); // +1 for NULL terminator
            if (!cmd_args) {
                set_response_error(response, "Failed to allocate memory for command line arguments");
                goto cleanup;
            }
            
            // Copy each argument
            for (int i = 0; i < args_count; i++) {
                cJSON *arg = cJSON_GetArrayItem(args_json, i);
                if (arg && cJSON_IsString(arg) && arg->valuestring) {
                    cmd_args[i] = strdup(arg->valuestring);
                    if (!cmd_args[i]) {
                        // Free previously allocated args
                        for (int j = 0; j < i; j++) {
                            free(cmd_args[j]);
                        }
                        free(cmd_args);
                        set_response_error(response, "Failed to allocate memory for command line argument");
                        goto cleanup;
                    }
                }
            }
            
            // Store in debugger state
            server->debugger_state.args = cmd_args;
            server->debugger_state.args_count = args_count;
            DAP_SERVER_DEBUG_LOG("Command line arguments: %d provided", args_count);
        }
    }
    
    // Call the implementation callback if registered
    bool callback_success = true;
    if (server->command_callbacks[DAP_CMD_LAUNCH]) {
        int callback_result = server->command_callbacks[DAP_CMD_LAUNCH](server);
        if (callback_result != 0) {
            callback_success = false;
            DAP_SERVER_DEBUG_LOG("Launch callback returned error: %d", callback_result);
        }
    } else {
        // Default implementation if no callback is registered
        DAP_SERVER_DEBUG_LOG("No launch callback registered, using default implementation");
        
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
        DAPSource *source = malloc(sizeof(DAPSource));
        if (source) {
            memset(source, 0, sizeof(DAPSource));
            
            // Use source path if provided, otherwise use program path
            const char *source_file = NULL;
            if (server->debugger_state.source_path) {
                source_file = server->debugger_state.source_path;
            } else if (server->debugger_state.program_path) {
                source_file = server->debugger_state.program_path;
            } else {
                // Neither source nor program path available!
                free(source);
                DAP_SERVER_DEBUG_LOG("Error: No source or program path available");
                set_response_error(response, "No source or program path available");
                return 0;
            }
            
            source->path = strdup(source_file);
            if (!source->path) {
                free(source);
                DAP_SERVER_DEBUG_LOG("Error: Failed to allocate memory for source path");
                set_response_error(response, "Failed to allocate memory for source path");
                return 0;
            }

            // Extract filename from path
            const char *filename = strrchr(source_file, '/');
            if (filename) {
                source->name = strdup(filename + 1);
            } else {
                source->name = strdup(source_file);
            }
            
            if (!source->name) {
                free(source->path);
                free(source);
                DAP_SERVER_DEBUG_LOG("Error: Failed to allocate memory for source name");
                set_response_error(response, "Failed to allocate memory for source name");
                return 0; // Let cleanup_command_context handle the resources
            }

            source->presentation_hint = DAP_SOURCE_PRESENTATION_NORMAL;
            source->origin = DAP_SOURCE_ORIGIN_UNKNOWN;

            server->current_source = source;
            server->debugger_state.source_line = 1;   // Start at line 1
            server->debugger_state.source_column = 1; // Start at column 1
            
            if (source->path && source->name) {
                DAP_SERVER_DEBUG_LOG("Set current source: path=%s, name=%s", 
                                  source->path, source->name);
            } else {
                DAP_SERVER_DEBUG_LOG("Set current source with incomplete information");
            }
        }
        
        // Send default events if no callback is registered
        DAP_SERVER_DEBUG_LOG("Sending stopped event after launch response");    
        // Stopped at entry point (program start).    
        dap_server_send_stopped_event(server, "entry", NULL);
    }

    // Per DAP spec and Microsoft's implementation, a launch response should be minimal with no body
    if (callback_success) {
        set_response_success(response, NULL);
        if (server->debugger_state.program_path) {
            DAP_SERVER_DEBUG_LOG("Launch response prepared for program: %s", 
                              server->debugger_state.program_path);
        } else {
            DAP_SERVER_DEBUG_LOG("Launch response prepared (no program path)");
        }
    } else {
        set_response_error(response, "Launch command failed");
    }

    // Note: We don't free the context resources here because they will be 
    // freed by cleanup_command_context after this function returns
    
    return 0;

cleanup:
    // Clean up allocated memory on error - let cleanup_command_context do the work
    cleanup_command_context(server);
    return -1;
}

int handle_attach(DAPServer *server, cJSON *args, DAPResponse *response)
{
    cJSON *pid = cJSON_GetObjectItem(args, "pid");
    if (!pid || !cJSON_IsNumber(pid))
    {
        response->success = false;
        response->error_message = strdup("Missing or invalid process ID");
        return 0;
    }

    server->is_running = true;
    server->attached = true;
    server->debugger_state.has_stopped = true;

    // Create a proper JSON object instead of using strdup
    cJSON *body = cJSON_CreateObject();
    if (!body) {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }
    
    set_response_success(response, body);
    // body is freed by set_response_success
    return 0;
}

int handle_disconnect(DAPServer* server, cJSON* args, DAPResponse* response) {
    if (!server || !response) {
        set_response_error(response, "Invalid server or response");
        return -1;
    }

    // Initialize the command context for disconnect
    server->current_command.type = DAP_CMD_DISCONNECT;
    memset(&server->current_command.context.disconnect, 0, sizeof(DisconnectCommandContext));
    
    // Parse arguments if present
    if (args) {
        // Check if terminateDebuggee option is set
        cJSON *terminate_json = cJSON_GetObjectItem(args, "terminateDebuggee");
        if (terminate_json && cJSON_IsBool(terminate_json)) {
            server->current_command.context.disconnect.terminate_debuggee = cJSON_IsTrue(terminate_json);
            DAP_SERVER_DEBUG_LOG("Disconnect with terminateDebuggee: %s", 
                               server->current_command.context.disconnect.terminate_debuggee ? "true" : "false");
        }
        
        // Check if suspendDebuggee option is set (available in newer DAP versions)
        cJSON *suspend_json = cJSON_GetObjectItem(args, "suspendDebuggee");
        if (suspend_json && cJSON_IsBool(suspend_json)) {
            server->current_command.context.disconnect.suspend_debuggee = cJSON_IsTrue(suspend_json);
            DAP_SERVER_DEBUG_LOG("Disconnect with suspendDebuggee: %s", 
                               server->current_command.context.disconnect.suspend_debuggee ? "true" : "false");
        }
        
        // Check if restart option is set
        cJSON *restart_json = cJSON_GetObjectItem(args, "restart");
        if (restart_json && cJSON_IsBool(restart_json)) {
            server->current_command.context.disconnect.restart = cJSON_IsTrue(restart_json);
            DAP_SERVER_DEBUG_LOG("Disconnect with restart: %s", 
                               server->current_command.context.disconnect.restart ? "true" : "false");
        }
    }
    
    // Call the implementation callback if registered
    bool callback_success = true;
    if (server->command_callbacks[DAP_CMD_DISCONNECT]) {
        DAP_SERVER_DEBUG_LOG("Calling disconnect implementation callback");
        int callback_result = server->command_callbacks[DAP_CMD_DISCONNECT](server);
        if (callback_result != 0) {
            callback_success = false;
            DAP_SERVER_DEBUG_LOG("Disconnect implementation callback failed with code %d", callback_result);
        }
    } else {
        DAP_SERVER_DEBUG_LOG("No disconnect implementation callback registered - using default behavior");
        // Default behavior: clean up breakpoints
        cleanup_breakpoints(server);
    }

    // Reset server state
    server->attached = false;
    
    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body) {
        set_response_error(response, "Failed to create response body");
        return -1;
    }
    
    // Set response according to callback result
    if (callback_success) {
        set_response_success(response, body);
    } else {
        cJSON_Delete(body); // Must delete body as we're not passing it to set_response_error
        set_response_error(response, "Disconnect command failed");
    }
    
    // Note: Context resources will be cleaned up by cleanup_command_context
    
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

int handle_stack_trace(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server->is_running || !server->attached)
    {
        set_response_error(response, "Debugger is not running or not attached");
        return -1;
    }

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Parse arguments
    int thread_id = 1; // Default to thread 1
    int start_frame = 0;
    int levels = 1;
    cJSON *format = NULL;

    if (args)
    {
        cJSON *thread_id_json = cJSON_GetObjectItem(args, "threadId");
        if (thread_id_json && cJSON_IsNumber(thread_id_json))
        {
            thread_id = thread_id_json->valueint;
        }

        cJSON *start_frame_json = cJSON_GetObjectItem(args, "startFrame");
        if (start_frame_json && cJSON_IsNumber(start_frame_json))
        {
            start_frame = start_frame_json->valueint;
        }

        cJSON *levels_json = cJSON_GetObjectItem(args, "levels");
        if (levels_json && cJSON_IsNumber(levels_json))
        {
            levels = levels_json->valueint;
        }

        format = cJSON_GetObjectItem(args, "format");
    }

    // Validate thread ID
    if (thread_id != 1)
    {
        cJSON_Delete(body);
        set_response_error(response, "Invalid thread ID - only thread 1 is supported");
        return -1;
    }

    // Validate start_frame and levels
    if (start_frame < 0 || levels < 1)
    {
        cJSON_Delete(body);
        set_response_error(response, "Invalid start_frame or levels parameter");
        return -1;
    }

    // Create stack frames array
    cJSON *frames = cJSON_CreateArray();
    if (!frames)
    {
        cJSON_Delete(body);
        set_response_error(response, "Failed to create frames array");
        return -1;
    }

    // Create current frame
    cJSON *frame = cJSON_CreateObject();
    if (!frame)
    {
        cJSON_Delete(body);
        cJSON_Delete(frames);
        set_response_error(response, "Failed to create frame object");
        return -1;
    }

    // Add frame properties
    cJSON_AddNumberToObject(frame, "id", start_frame);
    cJSON_AddStringToObject(frame, "name", "main");
    cJSON_AddNumberToObject(frame, "line", server->debugger_state.source_line);
    cJSON_AddNumberToObject(frame, "column", server->debugger_state.source_column);

    // Add source information if available
    if (server->current_source && server->current_source->path)
    {
        cJSON *source = cJSON_CreateObject();
        if (source)
        {
            // Check if the path ends with a binary extension
            const char *path = server->current_source->path;
            const char *ext = strrchr(path, '.');
            
            // Use a proper source file path, not the executable binary
            if (ext && (strcmp(ext, ".out") == 0 || strcmp(ext, ".exe") == 0 || strcmp(ext, ".bin") == 0))
            {
                // For binaries, replace with a proper source file
                // Extract the directory and base filename
                char dir_path[512] = {0};
                char base_name[128] = {0};
                
                const char *last_slash = strrchr(path, '/');
                if (last_slash) {
                    // Copy directory path
                    size_t dir_len = last_slash - path;
                    strncpy(dir_path, path, dir_len);
                    dir_path[dir_len] = '\0';
                    
                    // Copy base name without extension
                    const char *base = last_slash + 1;
                    size_t base_len = (ext - base);
                    strncpy(base_name, base, base_len);
                    base_name[base_len] = '\0';
                    
                    // Create source file path (same path, but with .asm extension)
                    char source_path[MAX_PATH_LENGTH] = {0};
                    size_t req_size = strlen(dir_path) + strlen(base_name) + 6; // +6 for "/", ".asm", and null terminator
                    if (req_size <= sizeof(source_path)) {
                        snprintf(source_path, sizeof(source_path), "%s/%s.asm", dir_path, base_name);
                        
                        // Use assembled source file path instead of binary
                        cJSON_AddStringToObject(source, "path", source_path);
                        cJSON_AddStringToObject(source, "name", strcat(base_name, ".asm"));
                    } else {
                        // Fallback if path would be too long
                        cJSON_AddStringToObject(source, "path", "/asm/source.asm");
                        cJSON_AddStringToObject(source, "name", "source.asm");
                    }
                } else {
                    // If we can't parse the path properly, still provide a better source path
                    char inferred_source[640];
                    char *dot_pos = strrchr(path, '.');
                    if (dot_pos) {
                        // Replace extension with .asm
                        size_t len = dot_pos - path;
                        strncpy(inferred_source, path, len);
                        inferred_source[len] = '\0';
                        strcat(inferred_source, ".asm");
                        
                        // Extract filename for the name field
                        const char *name = strrchr(inferred_source, '/');
                        name = name ? name + 1 : inferred_source;
                        
                        cJSON_AddStringToObject(source, "path", inferred_source);
                        cJSON_AddStringToObject(source, "name", name);
                    } else {
                        // Fallback if can't determine path
                        cJSON_AddStringToObject(source, "path", "/asm/source.asm");
                        cJSON_AddStringToObject(source, "name", "source.asm");
                    }
                }
            } else {
                // If it doesn't look like a binary, use the original path
                cJSON_AddStringToObject(source, "path", path);
                if (server->current_source->name)
                {
                    cJSON_AddStringToObject(source, "name", server->current_source->name);
                }
            }
            cJSON_AddItemToObject(frame, "source", source);
        }
    }

    // Add presentation hint if format is specified
    if (format)
    {
        cJSON *presentation_hint = cJSON_CreateObject();
        if (presentation_hint)
        {
            cJSON *parameters = cJSON_GetObjectItem(format, "parameters");
            if (parameters)
            {
                cJSON *show_hidden = cJSON_GetObjectItem(parameters, "showHidden");
                if (show_hidden && cJSON_IsBool(show_hidden))
                {
                    cJSON_AddBoolToObject(presentation_hint, "showHidden", cJSON_IsTrue(show_hidden));
                }
            }
            cJSON_AddItemToObject(frame, "presentationHint", presentation_hint);
        }
    }

    // Add frame to array
    cJSON_AddItemToArray(frames, frame);

    // Add frames array to body
    cJSON_AddItemToObject(body, "stackFrames", frames);

    // Respond with the actual number of frames
    cJSON_AddNumberToObject(body, "totalFrames", 1);

    // Set response
    set_response_success(response, body);
    return 0;
}

int handle_scopes(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server || !args || !response)
    {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    cJSON *frameId = cJSON_GetObjectItem(args, "frameId");
    if (!frameId || !cJSON_IsNumber(frameId))
    {
        set_response_error(response, "Invalid frame ID");
        return -1;
    }

    // Set up the command context
    server->current_command.type = DAP_CMD_SCOPES;
    server->current_command.request_seq = response->request_seq;
    server->current_command.context.scopes.frame_id = frameId->valueint;

    // Check if there's a registered callback for this command
    if (server->command_callbacks[DAP_CMD_SCOPES])
    {
        int result = server->command_callbacks[DAP_CMD_SCOPES](server);
        if (result == 0)
        {
            // Callback handled the command - response will be sent by the callback
            return 0;
        }
        // If the callback returns non-zero, fall back to default implementation
    }

    // Create response body with scopes
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Add scopes array
    cJSON *scopes = cJSON_CreateArray();
    if (!scopes)
    {
        cJSON_Delete(body);
        set_response_error(response, "Failed to create scopes array");
        return -1;
    }

    // Add CPU Registers scope (always available, even at entry point)
    cJSON *registersScope = cJSON_CreateObject();
    if (registersScope)
    {
        cJSON_AddStringToObject(registersScope, "name", "CPU Registers");
        cJSON_AddNumberToObject(registersScope, "variablesReference", 1);
        cJSON_AddNumberToObject(registersScope, "namedVariables", 8); // Number of CPU registers
        cJSON_AddBoolToObject(registersScope, "expensive", false);
        cJSON_AddStringToObject(registersScope, "presentationHint", "registers");
        cJSON_AddItemToArray(scopes, registersScope);
    }

    // Add CPU Flags scope (always available, even at entry point)
    cJSON *flagsScope = cJSON_CreateObject();
    if (flagsScope)
    {
        cJSON_AddStringToObject(flagsScope, "name", "CPU Flags");
        cJSON_AddNumberToObject(flagsScope, "variablesReference", 1001);
        cJSON_AddNumberToObject(flagsScope, "namedVariables", 4); // Number of CPU flags
        cJSON_AddBoolToObject(flagsScope, "expensive", false);
        cJSON_AddStringToObject(flagsScope, "presentationHint", "registers");
        cJSON_AddItemToArray(scopes, flagsScope);
    }

    // Add Internal Registers scope (always available, even at entry point)
    cJSON *internalScope = cJSON_CreateObject();
    if (internalScope)
    {
        cJSON_AddStringToObject(internalScope, "name", "Internal Registers");
        cJSON_AddNumberToObject(internalScope, "variablesReference", 4);
        cJSON_AddNumberToObject(internalScope, "namedVariables", 2); // Number of internal registers
        cJSON_AddBoolToObject(internalScope, "expensive", false);
        cJSON_AddStringToObject(internalScope, "presentationHint", "registers");
        cJSON_AddItemToArray(scopes, internalScope);
    }

    cJSON_AddItemToObject(body, "scopes", scopes);
    set_response_success(response, body);
    return 0;
}

int handle_variables(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server || !args || !response)
    {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    cJSON *variablesReference = cJSON_GetObjectItem(args, "variablesReference");
    if (!variablesReference || !cJSON_IsNumber(variablesReference))
    {
        set_response_error(response, "Invalid variables reference");
        return -1;
    }

    // Initialize the command context for variables
    server->current_command.type = DAP_CMD_VARIABLES;
    server->current_command.request_seq = response->request_seq;
    memset(&server->current_command.context.variables, 0, sizeof(VariablesCommandContext));
    
    // Set the required variables reference
    server->current_command.context.variables.variables_reference = variablesReference->valueint;
    
    // Parse optional filter
    cJSON *filter = cJSON_GetObjectItem(args, "filter");
    if (filter && cJSON_IsString(filter))
    {
        if (strcmp(filter->valuestring, "indexed") == 0)
        {
            server->current_command.context.variables.filter = 1; // indexed
        }
        else if (strcmp(filter->valuestring, "named") == 0)
        {
            server->current_command.context.variables.filter = 2; // named
        }
    }
    
    // Parse optional start
    cJSON *start = cJSON_GetObjectItem(args, "start");
    if (start && cJSON_IsNumber(start))
    {
        server->current_command.context.variables.start = start->valueint;
    }
    
    // Parse optional count
    cJSON *count = cJSON_GetObjectItem(args, "count");
    if (count && cJSON_IsNumber(count))
    {
        server->current_command.context.variables.count = count->valueint;
    }
    
    // Parse optional format
    cJSON *format = cJSON_GetObjectItem(args, "format");
    if (format && cJSON_IsString(format))
    {
        server->current_command.context.variables.format = strdup(format->valuestring);
    }
    
    // Check if there's a registered callback for this command
    if (server->command_callbacks[DAP_CMD_VARIABLES])
    {
        int result = server->command_callbacks[DAP_CMD_VARIABLES](server);
        if (result == 0)
        {
            // Callback handled the command - response will be sent by the callback
            return 0;
        }
        // If the callback returns non-zero, fall back to default implementation
    }

    // Create response body with variables
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Add variables array
    cJSON *variables = cJSON_CreateArray();
    if (!variables)
    {
        cJSON_Delete(body);
        set_response_error(response, "Failed to create variables array");
        return -1;
    }

    int ref = variablesReference->valueint;
    Register *reg_array = NULL;
    size_t reg_count = 0;
    cJSON *readScope = NULL;
    cJSON *writeScope = NULL;

    // Select appropriate register array based on reference
    switch (ref)
    {
    case 1: // CPU Registers
        reg_array = cpu_registers;
        reg_count = NUM_REGISTERS;
        break;
    case 2: // Internal Read Registers
        reg_array = internal_read_registers;
        reg_count = NUM_INTERNAL_READ_REGISTERS;
        break;
    case 3: // Internal Write Registers
        reg_array = internal_write_registers;
        reg_count = NUM_INTERNAL_WRITE_REGISTERS;
        break;
    case 4: // Internal Registers parent scope
        // Add subscopes for internal registers with detailed information
        readScope = cJSON_CreateObject();
        if (readScope)
        {
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
        if (writeScope)
        {
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
    case 1001: // Status Register Flags
        // Add status flags as variables
        for (size_t i = 0; i < NUM_STATUS_FLAGS; i++)
        {
            cJSON *var = cJSON_CreateObject();
            if (var)
            {
                cJSON_AddStringToObject(var, "name", status_flags[i].name);
                cJSON_AddStringToObject(var, "value", status_flags[i].value ? "1" : "0");
                cJSON_AddStringToObject(var, "type", status_flags[i].type);
                cJSON_AddNumberToObject(var, "variablesReference", 0);
                cJSON_AddItemToArray(variables, var);
            }
        }
        break;
    default:
    {
        // Create error response
        cJSON_Delete(body);
        cJSON_Delete(variables);
        set_response_error(response, "Invalid variables reference - no such variable group exists");
        return 0;
    }
    }

    // Add registers as variables if not handling status flags or internal parent scope
    if (ref != 1001 && ref != 4 && reg_array)
    {
        for (size_t i = 0; i < reg_count; i++)
        {
            cJSON *var = cJSON_CreateObject();
            if (var)
            {
                cJSON_AddStringToObject(var, "name", reg_array[i].name);
                char value_str[32];
                if (strcmp(reg_array[i].type, "octal") == 0)
                {
                    snprintf(value_str, sizeof(value_str), "%o", reg_array[i].value);
                }
                else
                {
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
    
    // Free any allocated memory for the variables context
    if (server->current_command.context.variables.format)
    {
        free((void*)server->current_command.context.variables.format);
        server->current_command.context.variables.format = NULL;
    }
    
    return 0;
}

static void set_response_success(DAPResponse *response, cJSON *body)
{
    if (response)
    {
        response->success = true;
        response->error_message = NULL;
        if (body)
        {
            response->data = cJSON_PrintUnformatted(body);
            response->data_size = strlen(response->data);
            // Free the body after using it to avoid memory leaks
            cJSON_Delete(body);
        }
        else
        {
            response->data = NULL;
            response->data_size = 0;
        }
    }
}

// Helper functions for response handling
static void set_response_error(DAPResponse *response, const char *error_message)
{
    if (response)
    {
        response->success = false;
        response->error_message = strdup(error_message);
        response->data = NULL;
        response->data_size = 0;
    }
}

int handle_terminate(DAPServer* server, cJSON* args, DAPResponse* response) {
    (void)args; // Unused parameter
    
    if (!server || !response) {
        set_response_error(response, "Invalid server or response");
        return -1;
    }

    DAP_SERVER_DEBUG_LOG("Terminating debuggee");
    
    // Create response body
    cJSON* body = cJSON_CreateObject();
    if (!body) {
        set_response_error(response, "Failed to create response body");
        return -1;
    }
    
    // If a terminate callback is registered, call it
    if (server->command_callbacks[DAP_CMD_TERMINATE]) {
        int result = server->command_callbacks[DAP_CMD_TERMINATE](server);
        if (result != 0) {
            cJSON_Delete(body);
            set_response_error(response, "Terminate command callback failed");
            return -1;
        }
    }
    
    // Send terminated event
    cJSON* event_body = cJSON_CreateObject();
    if (event_body) {
        // The terminated event can optionally include a 'restart' attribute
        dap_server_send_event(server, "terminated", event_body);
    }
    
    set_response_success(response, body);
    return 0;
}

int handle_restart(DAPServer* server, cJSON* args, DAPResponse* response) {
    if (!server || !response) {
        set_response_error(response, "Invalid server or response");
        return -1;
    }

    // Initialize the command context for restart
    server->current_command.type = DAP_CMD_RESTART;
    memset(&server->current_command.context.restart, 0, sizeof(RestartCommandContext));
    
    // Parse arguments if present
    if (args) {
        // Check if noDebug option is set
        cJSON *no_debug_json = cJSON_GetObjectItem(args, "noDebug");
        if (no_debug_json && cJSON_IsBool(no_debug_json) && cJSON_IsTrue(no_debug_json)) {
            server->current_command.context.restart.no_debug = true;
            DAP_SERVER_DEBUG_LOG("Restart with noDebug option");
        }
        
        // Parse the arguments field which can contain launch or attach arguments
        cJSON *arguments_json = cJSON_GetObjectItem(args, "arguments");
        if (arguments_json && cJSON_IsObject(arguments_json)) {
            // Store the arguments in the restart context
            server->current_command.context.restart.restart_args = cJSON_Duplicate(arguments_json, 1);
            if (!server->current_command.context.restart.restart_args) {
                DAP_SERVER_DEBUG_LOG("Failed to duplicate restart arguments");
            }
        }
    }
    
    // Call the implementation callback if registered
    bool callback_success = true;
    if (server->command_callbacks[DAP_CMD_RESTART]) {
        DAP_SERVER_DEBUG_LOG("Calling restart implementation callback");
        int callback_result = server->command_callbacks[DAP_CMD_RESTART](server);
        if (callback_result != 0) {
            callback_success = false;
            DAP_SERVER_DEBUG_LOG("Restart implementation callback failed with code %d", callback_result);
        }
    } else {
        DAP_SERVER_DEBUG_LOG("No restart implementation callback registered");
        // If no callback is registered, we still return success
        // but don't perform any actual restart logic
    }

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body) {
        set_response_error(response, "Failed to create response body");
        return -1;
    }
    
    // Set response according to callback result
    if (callback_success) {
        set_response_success(response, body);
        DAP_SERVER_DEBUG_LOG("Restart command succeeded");
    } else {
        cJSON_Delete(body); // Must delete body as we're not passing it to set_response_error
        set_response_error(response, "Restart command failed");
    }
    
    // Note: Context resources will be cleaned up by cleanup_command_context
    
    return 0;
}

int handle_set_exception_breakpoints(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server || !args || !response)
    {
        set_response_error(response, "Invalid arguments");
        return -1;
    }
    
    DAP_SERVER_DEBUG_LOG("Handling setExceptionBreakpoints request");
    
    // Initialize the command context
    server->current_command.type = DAP_CMD_SET_EXCEPTION_BREAKPOINTS;
    memset(&server->current_command.context.exception, 0, sizeof(ExceptionBreakpointCommandContext));
    
    // "filters" (required) - Array of exception filter IDs to activate
    cJSON *filters = cJSON_GetObjectItem(args, "filters");
    if (!filters || !cJSON_IsArray(filters)) {
        // Return success with empty breakpoints array instead of an error
        cJSON *body = cJSON_CreateObject();
        if (!body) {
            set_response_error(response, "Failed to create response body");
            return 0;
        }
        
        // According to DAP spec, the response must include a "breakpoints" array
        cJSON *breakpoints = cJSON_CreateArray();
        if (!breakpoints) {
            cJSON_Delete(body);
            set_response_error(response, "Failed to create breakpoints array");
            return 0;
        }
        
        cJSON_AddItemToObject(body, "breakpoints", breakpoints);
        set_response_success(response, body);
        return 0;
    }
    
    // Get the number of filters
    int filter_count = cJSON_GetArraySize(filters);
    
    // Allocate arrays for filter IDs and conditions
    const char **filter_ids = NULL;
    const char **filter_conditions = NULL;
    
    if (filter_count > 0) {
        filter_ids = calloc(filter_count, sizeof(const char*));
        if (!filter_ids) {
            set_response_error(response, "Failed to allocate memory for filter IDs");
            return 0;
        }
        
        // "filterOptions" (optional) - Additional configuration for exception filters
        cJSON *filter_options = cJSON_GetObjectItem(args, "filterOptions");
        
        // We'll also track conditions if filterOptions is provided
        if (filter_options && cJSON_IsArray(filter_options)) {
            filter_conditions = calloc(filter_count, sizeof(const char*));
            if (!filter_conditions) {
                free((void*)filter_ids);
                set_response_error(response, "Failed to allocate memory for filter conditions");
                return 0;
            }
        }
        
        // Extract each filter ID and any matching conditions from filterOptions
        for (int i = 0; i < filter_count; i++) {
            cJSON *filter = cJSON_GetArrayItem(filters, i);
            if (filter && cJSON_IsString(filter)) {
                filter_ids[i] = strdup(filter->valuestring);
                
                // Look for matching filter condition if filter_options is provided
                if (filter_conditions && filter_options && cJSON_IsArray(filter_options)) {
                    int option_count = cJSON_GetArraySize(filter_options);
                    for (int j = 0; j < option_count; j++) {
                        cJSON *option = cJSON_GetArrayItem(filter_options, j);
                        if (!option || !cJSON_IsObject(option)) continue;
                        
                        // "filterId" - Matches ID from filters array
                        cJSON *filter_id = cJSON_GetObjectItem(option, "filterId");
                        if (!filter_id || !cJSON_IsString(filter_id)) continue;
                        
                        if (strcmp(filter_id->valuestring, filter->valuestring) == 0) {
                            // Found matching filter option
                            // "condition" - Expression for conditional exception breakpoints
                            cJSON *condition = cJSON_GetObjectItem(option, "condition");
                            if (condition && cJSON_IsString(condition)) {
                                filter_conditions[i] = strdup(condition->valuestring);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    
    // Store pointers in the context
    server->current_command.context.exception.filters = filter_ids;
    server->current_command.context.exception.filter_count = filter_count;
    server->current_command.context.exception.conditions = filter_conditions;
    server->current_command.context.exception.condition_count = filter_conditions ? filter_count : 0;
    
    // Call the callback if it's registered
    if (server->command_callbacks[DAP_CMD_SET_EXCEPTION_BREAKPOINTS]) {
        // Call the implementation callback
        server->command_callbacks[DAP_CMD_SET_EXCEPTION_BREAKPOINTS](server);
    }
    
    // Create response with breakpoints array matching filter count
    cJSON *body = cJSON_CreateObject();
    if (!body) {
        // Free allocated memory
        free_filter_arrays(filter_ids, filter_conditions, filter_count);
        set_response_error(response, "Failed to create response body");
        return 0;
    }
    
    // "breakpoints" array - contains status info for each exception breakpoint filter
    cJSON *breakpoints = cJSON_CreateArray();
    if (!breakpoints) {
        cJSON_Delete(body);
        // Free allocated memory
        free_filter_arrays(filter_ids, filter_conditions, filter_count);
        set_response_error(response, "Failed to create breakpoints array");
        return 0;
    }
    
    // Add one breakpoint object for each filter
    for (int i = 0; i < filter_count; i++) {
        cJSON *breakpoint = cJSON_CreateObject();
        if (!breakpoint) {
            cJSON_Delete(body);
            cJSON_Delete(breakpoints);
            // Free allocated memory
            free_filter_arrays(filter_ids, filter_conditions, filter_count);
            set_response_error(response, "Failed to create breakpoint object");
            return 0;
        }
        
        // "verified" (required) - Whether the breakpoint is valid and could be set
        cJSON_AddBoolToObject(breakpoint, "verified", true);
        
        // "id" (optional) - Unique identifier for this breakpoint
        // Use base ID of 1000 to differentiate from regular breakpoints
        cJSON_AddNumberToObject(breakpoint, "id", 1000 + i);
        
        // "message" (optional) - Error or information message about the breakpoint
        if (filter_ids[i]) {
            char message[128];
            snprintf(message, sizeof(message), "Exception breakpoint: %s", filter_ids[i]);
            cJSON_AddStringToObject(breakpoint, "message", message);
        }
        
        // Add the breakpoint to the array
        cJSON_AddItemToArray(breakpoints, breakpoint);
    }
    
    cJSON_AddItemToObject(body, "breakpoints", breakpoints);
    set_response_success(response, body);
    
    // Free allocated memory - the callback should not have freed any of this
    free_filter_arrays(filter_ids, filter_conditions, filter_count);
    
    return 0;
}

/**
 * @brief Helper function to free filter arrays and their contents
 * 
 * @param filter_ids Array of filter ID strings
 * @param filter_conditions Array of filter condition strings
 * @param count Number of filters
 */
void free_filter_arrays(const char **filter_ids, const char **filter_conditions, int count) {
    if (!filter_ids || !filter_conditions || count <= 0) {
        return;
    }
    
    // Free each filter ID and condition string
    for (int i = 0; i < count; i++) {
        if (filter_ids[i]) {
            free((void*)filter_ids[i]);
        }
        if (filter_conditions[i]) {
            free((void*)filter_conditions[i]);
        }
    }
    
    // Free the arrays themselves
    free((void*)filter_ids);
    free((void*)filter_conditions);
}

int handle_source(DAPServer *server, cJSON *args, DAPResponse *response)
{
    (void)server; // Mark as unused
    if (!args || !response)
    {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    cJSON *source = cJSON_GetObjectItem(args, "source");
    if (!source)
    {
        set_response_error(response, "No source specified");
        return -1;
    }

    cJSON *path = cJSON_GetObjectItem(source, "path");
    cJSON *sourceReference = cJSON_GetObjectItem(source, "sourceReference");

    // Check if we have a path or reference
    if ((!path || !cJSON_IsString(path)) &&
        (!sourceReference || !cJSON_IsNumber(sourceReference)))
    {
        set_response_error(response, "Invalid source path or reference");
        return -1;
    }

    // Create response body with source content
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Try to read source file if a path is provided
    if (path && cJSON_IsString(path))
    {
        const char *file_path = path->valuestring;

        // Check if path is a directory
        struct stat path_stat;
        if (stat(file_path, &path_stat) == 0 && S_ISDIR(path_stat.st_mode))
        {
            cJSON_Delete(body);
            set_response_error(response, "Cannot read directory as source file");
            return -1;
        }

        FILE *f = fopen(file_path, "r");

        if (f)
        {
            // Get file size
            fseek(f, 0, SEEK_END);
            long file_size = ftell(f);
            fseek(f, 0, SEEK_SET);

            // Validate file size to avoid allocation issues
            if (file_size <= 0 || file_size > 10 * 1024 * 1024)
            { // Max 10MB for safety
                fclose(f);
                cJSON_Delete(body);
                set_response_error(response, "Invalid file size or file too large");
                return -1;
            }

            // Read file content
            char *content = malloc((size_t)file_size + 1);
            if (content)
            {
                size_t bytes_read = fread(content, 1, (size_t)file_size, f);
                content[bytes_read] = '\0'; // Null-terminate

                // Add content to response
                cJSON_AddStringToObject(body, "content", content);
                cJSON_AddStringToObject(body, "mimeType", "text/plain");

                free(content);
            }
            else
            {
                cJSON_Delete(body);
                fclose(f);
                set_response_error(response, "Failed to allocate memory for file content");
                return -1;
            }

            fclose(f);
        }
        else
        {
            // File could not be opened, return an error
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "Failed to open source file: %s", file_path);
            cJSON_Delete(body);
            set_response_error(response, error_msg);
            return -1;
        }
    }
    // Handle source reference (in-memory source)
    else if (sourceReference && cJSON_IsNumber(sourceReference))
    {
        int ref = sourceReference->valueint;

        // In a real implementation, this would look up source by reference ID
        // For the mock, we'll return a placeholder
        char source_content[256];
        snprintf(source_content, sizeof(source_content),
                 "// Generated source for reference %d\n"
                 "// This would be actual source code in a real implementation\n"
                 "int main() {\n"
                 "    return 0;\n"
                 "}\n",
                 ref);

        cJSON_AddStringToObject(body, "content", source_content);
        cJSON_AddStringToObject(body, "mimeType", "text/plain");
    }

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

int handle_threads(DAPServer *server, cJSON *args, DAPResponse *response)
{
    (void)args; // Mark as unused

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    // Create threads array
    cJSON *threads = cJSON_CreateArray();
    if (!threads)
    {
        cJSON_Delete(body);
        response->success = false;
        response->error_message = strdup("Failed to create threads array");
        return 0;
    }

    // Create thread object
    cJSON *thread = cJSON_CreateObject();
    if (!thread)
    {
        cJSON_Delete(body);
        cJSON_Delete(threads);
        response->success = false;
        response->error_message = strdup("Failed to create thread object");
        return 0;
    }

    // Add thread properties
    cJSON_AddNumberToObject(thread, "id", 1); // Always use thread ID 1
    cJSON_AddStringToObject(thread, "name", "CPU thread");

    // Add thread state based on debugger state
    if (!server->is_running || !server->attached)
    {
        cJSON_AddStringToObject(thread, "state", "stopped");
    }
    else if (server->debugger_state.has_stopped)
    {
        cJSON_AddStringToObject(thread, "state", "paused");
    }
    else
    {
        cJSON_AddStringToObject(thread, "state", "running");
    }

    // Add thread to array
    cJSON_AddItemToArray(threads, thread);

    // Add threads array to body
    cJSON_AddItemToObject(body, "threads", threads);

    // Set response
    set_response_success(response, body);
    return 0;
}

/**
 * @brief Handle the setVariable command
 * 
 * This function implements the DAP setVariable command which allows clients to modify
 * the value of a variable in the debugger. The command requires:
 * - variablesReference: The reference of the variable container
 * - name: The name of the variable to modify
 * - value: The new value to set
 * 
 * Optional parameters:
 * - format: Specifies how the value should be formatted
 * 
 * The response includes:
 * - value: The new value of the variable
 * - type: The type of the variable (if available)
 * - variablesReference: Reference for child variables (if any)
 * - namedVariables: Number of named child variables
 * - indexedVariables: Number of indexed child variables
 * - memoryReference: Memory reference for the variable (if applicable)
 * 
 * @param server The DAP server instance
 * @param args The command arguments as a JSON object
 * @param response The response structure to fill
 * @return int 0 on success, non-zero on failure
 */
int handle_set_variable(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server || !args || !response) {
        return -1;
    }

    // Parse required arguments
    cJSON *variablesReference = cJSON_GetObjectItem(args, "variablesReference");
    cJSON *name = cJSON_GetObjectItem(args, "name");
    cJSON *value = cJSON_GetObjectItem(args, "value");

    // Validate required arguments
    if (!variablesReference || !name || !value) {
        set_response_error(response, "Missing required arguments");
        return -1;
    }

    // Store command context for the implementation callback
    server->current_command.type = DAP_CMD_SET_VARIABLE;
    server->current_command.context.set_variable.variables_reference = variablesReference->valueint;
    server->current_command.context.set_variable.name = strdup(name->valuestring);
    server->current_command.context.set_variable.value = strdup(value->valuestring);

    // Parse optional format argument
    cJSON *format = cJSON_GetObjectItem(args, "format");
    if (format) {
        server->current_command.context.set_variable.format = strdup(format->valuestring);
    }

    // Check if there's a registered callback for this command
    if (server->command_callbacks[DAP_CMD_SET_VARIABLE]) {
        int result = server->command_callbacks[DAP_CMD_SET_VARIABLE](server);
        if (result == 0) {
            // Callback handled the command - response will be sent by the callback
            return 0;
        }
        // If the callback returns non-zero, fall back to default implementation
    }

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body) {
        cleanup_command_context(server);
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Add required fields
    cJSON_AddStringToObject(body, "value", value->valuestring);

    // Add optional fields if available
    if (format) {
        cJSON_AddStringToObject(body, "type", "string"); // Example type
        cJSON_AddNumberToObject(body, "variablesReference", 0);
        cJSON_AddNumberToObject(body, "namedVariables", 0);
        cJSON_AddNumberToObject(body, "indexedVariables", 0);
        cJSON_AddStringToObject(body, "memoryReference", "");
    }

    set_response_success(response, body);
    cJSON_Delete(body);
    return 0;
}

