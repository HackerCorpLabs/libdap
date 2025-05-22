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
#include <ctype.h>

#include "dap_server.h"
#include "dap_error.h"
#include "dap_types.h"
#include "dap_transport.h"
#include "dap_protocol.h"
#include "dap_server_cmds.h"
#include <cjson/cJSON.h>

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
char *base64_encode(const uint8_t *data, size_t len)
{
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Calculate the length of the output string
    size_t output_len = 4 * ((len + 2) / 3) + 1; // +1 for null terminator

    // Allocate memory for the output
    char *output = malloc(output_len);
    if (!output)
    {
        return NULL;
    }

    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4)
    {
        uint32_t triplet = data[i] << 16;
        if (i + 1 < len)
            triplet |= data[i + 1] << 8;
        if (i + 2 < len)
            triplet |= data[i + 2];

        output[j] = base64_chars[(triplet >> 18) & 0x3F];
        output[j + 1] = base64_chars[(triplet >> 12) & 0x3F];
        output[j + 2] = (i + 1 < len) ? base64_chars[(triplet >> 6) & 0x3F] : '=';
        output[j + 3] = (i + 2 < len) ? base64_chars[triplet & 0x3F] : '=';
    }

    output[j] = '\0';
    return output;
}

/// @brief Convert a string to a uint32_t. Supports hex, octal, and decimal.
/// @param str 
/// @return 
uint32_t string_to_uint32(const char *str)
{
    if (!str) {
        return 0;
    }

    // Skip leading whitespace
    while (*str && isspace(*str)) {
        str++;
    }

    // Check for hex prefix
    if (strncmp(str, "0x", 2) == 0) {
        return strtoul(str, NULL, 16);
    }

    // Check for octal (6 chars long and starts with 0 or 1)
    if (strlen(str) == 6 && (str[0] == '0' || str[0] == '1')) {
        return strtoul(str, NULL, 8);
    }

    // Default to decimal
    return strtoul(str, NULL, 10);
}

// Forward declarations for helper functions
void free_breakpoints_array(const DAPBreakpoint *breakpoints, int count);
void free_filter_arrays(const char **filter_ids, const char **filter_conditions, int count);
void free_variable_array(DAPVariable *variables, int count);
static void set_response_success(DAPResponse *response, cJSON *body);
static void set_response_error(DAPResponse *response, const char *error_message);
int mock_handle_stack_trace(DAPServer *server);

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
typedef struct
{
    const char *name; // Name of the capability in the DAP spec
    bool supported;   // Whether the capability is supported
} DAPCapability;

/**
 * @brief Global array of server capabilities
 * Indexed by DAPCapabilityID enum values
 * All capabilities are initialized as false by default
 */
static DAPCapability server_capabilities[DAP_CAP_COUNT] = {
    {"supportsConfigurationDoneRequest", false},
    {"supportsFunctionBreakpoints", false},
    {"supportsConditionalBreakpoints", false},
    {"supportsHitConditionalBreakpoints", false},
    {"supportsEvaluateForHovers", false},
    {"supportsSetVariable", false},
    {"supportsCompletionsRequest", false},
    {"supportsModulesRequest", false},
    {"supportsRestartRequest", false},
    {"supportsExceptionOptions", false},
    {"supportsValueFormattingOptions", false},
    {"supportsExceptionInfoRequest", false},
    {"supportTerminateDebuggee", false}, // NOTE! This is not the same as terminateRequest. And be aware of the single vs plural in the name. Its single!
    {"supportsDelayedStackTraceLoading", false},
    {"supportsLoadedSourcesRequest", false},
    {"supportsLogPoints", false},
    {"supportsTerminateThreadsRequest", false},
    {"supportsSetExpression", false},
    {"supportsTerminateRequest", false},
    {"supportsDataBreakpoints", false},
    {"supportsReadMemoryRequest", false},
    {"supportsWriteMemoryRequest", false},
    {"supportsDisassembleRequest", false},
    {"supportsCancelRequest", false},
    {"supportsBreakpointLocationsRequest", false},
    {"supportsSteppingGranularity", false},
    {"supportsInstructionBreakpoints", false},
    {"supportsExceptionFilterOptions", false},
    {"supportsSingleThreadExecutionRequests", false},
    {"supportsStepBack", false},
    {"supportsRestartFrame", false},
    {"supportsGotoTargetsRequest", false},
    {"supportsStepInTargetsRequest", false},
    {"supportsClipboardContext", false},
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
    if (capability_id >= 0 && capability_id < DAP_CAP_COUNT)
    {
        server_capabilities[capability_id].supported = supported;
        return 0;
    }
    return -1;
}

static int dap_server_execute_callback(DAPServer *server, DAPCommandType cmd)
{
    if (!server)
    {
        return -1;
    }

    // Check if the command type is valid
    if (cmd < 0 || cmd >= DAP_CMD_MAX)
    {
        return -1;
    }

    // Call the implementation callback for the command
    DAPCommandCallback pre = server->command_callbacks[DAP_WAIT_FOR_DEBUGGER];
    DAPCommandCallback callback = server->command_callbacks[cmd];
    DAPCommandCallback post = server->command_callbacks[DAP_RELEASE_DEBUGGER];

    if (callback)
    {
        if (pre) {
            int pre_result = pre(server);          // Wait for the debugger to be ready
            if (pre_result < 0)
            {
                return pre_result;
            }
        }
        
        int result = callback(server); // DO the command
        if (post) post(server);        // Release the debugger
        return result;
    }
    else
    {
        DAP_SERVER_DEBUG_LOG("No implementation callback for command %d", cmd);
        return -1;
    }
}

/**
 * @brief Enum for DAP exception filter types
 *
 * Per DAP specification, an ExceptionBreakpointsFilter represents a specific way of handling
 * exceptions that can be enabled or disabled by the client. Each filter is shown in the UI
 * as a checkbox option for configuring how exceptions are dealt with during debugging.
 */
typedef enum
{
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
typedef struct
{
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
    {"all", "All Exceptions", "Break on all exceptions", false},
    {"uncaught", "Uncaught Exceptions", "Break on uncaught exceptions", true},
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

    while ((capability_id = va_arg(args, DAPCapabilityID)) != DAP_CAP_COUNT)
    {
        bool supported = va_arg(args, int); // bool is promoted to int in va_arg
        if (dap_server_set_capability(capability_id, supported) == 0)
        {
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
        if (client_id && cJSON_IsString(client_id))
        {
            if (server->client_capabilities.clientID)
            {
                free(server->client_capabilities.clientID);
            }
            server->client_capabilities.clientID = strdup(client_id->valuestring);
        }

        cJSON *client_name = cJSON_GetObjectItem(args, "clientName");
        if (client_name && cJSON_IsString(client_name))
        {
            if (server->client_capabilities.clientName)
            {
                free(server->client_capabilities.clientName);
            }
            server->client_capabilities.clientName = strdup(client_name->valuestring);
        }

        cJSON *adapter_id = cJSON_GetObjectItem(args, "adapterID");
        if (adapter_id && cJSON_IsString(adapter_id))
        {
            if (server->client_capabilities.adapterID)
            {
                free(server->client_capabilities.adapterID);
            }
            server->client_capabilities.adapterID = strdup(adapter_id->valuestring);
        }

        cJSON *locale = cJSON_GetObjectItem(args, "locale");
        if (locale && cJSON_IsString(locale))
        {
            if (server->client_capabilities.locale)
            {
                free(server->client_capabilities.locale);
            }
            server->client_capabilities.locale = strdup(locale->valuestring);
        }

        // Store path format (path or uri)
        cJSON *path_format = cJSON_GetObjectItem(args, "pathFormat");
        if (path_format && cJSON_IsString(path_format))
        {
            if (server->client_capabilities.pathFormat)
            {
                free(server->client_capabilities.pathFormat);
            }
            server->client_capabilities.pathFormat = strdup(path_format->valuestring);
        }

        // Store line/column formatting preferences
        cJSON *lines_start_at_1 = cJSON_GetObjectItem(args, "linesStartAt1");
        if (lines_start_at_1 && cJSON_IsBool(lines_start_at_1))
        {
            server->client_capabilities.linesStartAt1 = cJSON_IsTrue(lines_start_at_1);
        }
        else
        {
            server->client_capabilities.linesStartAt1 = true; // Default to 1-based
        }

        cJSON *columns_start_at_1 = cJSON_GetObjectItem(args, "columnsStartAt1");
        if (columns_start_at_1 && cJSON_IsBool(columns_start_at_1))
        {
            server->client_capabilities.columnsStartAt1 = cJSON_IsTrue(columns_start_at_1);
        }
        else
        {
            server->client_capabilities.columnsStartAt1 = true; // Default to 1-based
        }

        // Store supported client features
        cJSON *supports_variable_type = cJSON_GetObjectItem(args, "supportsVariableType");
        if (supports_variable_type && cJSON_IsBool(supports_variable_type))
        {
            server->client_capabilities.supportsVariableType = cJSON_IsTrue(supports_variable_type);
        }

        cJSON *supports_variable_paging = cJSON_GetObjectItem(args, "supportsVariablePaging");
        if (supports_variable_paging && cJSON_IsBool(supports_variable_paging))
        {
            server->client_capabilities.supportsVariablePaging = cJSON_IsTrue(supports_variable_paging);
        }

        cJSON *supports_run_in_terminal = cJSON_GetObjectItem(args, "supportsRunInTerminalRequest");
        if (supports_run_in_terminal && cJSON_IsBool(supports_run_in_terminal))
        {
            server->client_capabilities.supportsRunInTerminalRequest = cJSON_IsTrue(supports_run_in_terminal);
        }

        cJSON *supports_memory_references = cJSON_GetObjectItem(args, "supportsMemoryReferences");
        if (supports_memory_references && cJSON_IsBool(supports_memory_references))
        {
            server->client_capabilities.supportsMemoryReferences = cJSON_IsTrue(supports_memory_references);
        }

        cJSON *supports_progress_reporting = cJSON_GetObjectItem(args, "supportsProgressReporting");
        if (supports_progress_reporting && cJSON_IsBool(supports_progress_reporting))
        {
            server->client_capabilities.supportsProgressReporting = cJSON_IsTrue(supports_progress_reporting);
        }

        cJSON *supports_invalidated_event = cJSON_GetObjectItem(args, "supportsInvalidatedEvent");
        if (supports_invalidated_event && cJSON_IsBool(supports_invalidated_event))
        {
            server->client_capabilities.supportsInvalidatedEvent = cJSON_IsTrue(supports_invalidated_event);
        }

        cJSON *supports_memory_event = cJSON_GetObjectItem(args, "supportsMemoryEvent");
        if (supports_memory_event && cJSON_IsBool(supports_memory_event))
        {
            server->client_capabilities.supportsMemoryEvent = cJSON_IsTrue(supports_memory_event);
        }

        cJSON *supports_ansi_styling = cJSON_GetObjectItem(args, "supportsANSIStyling");
        if (supports_ansi_styling && cJSON_IsBool(supports_ansi_styling))
        {
            server->client_capabilities.supportsANSIStyling = cJSON_IsTrue(supports_ansi_styling);
        }

        cJSON *supports_args_shell = cJSON_GetObjectItem(args, "supportsArgsCanBeInterpretedByShell");
        if (supports_args_shell && cJSON_IsBool(supports_args_shell))
        {
            server->client_capabilities.supportsArgsCanBeInterpretedByShell = cJSON_IsTrue(supports_args_shell);
        }

        cJSON *supports_start_debugging = cJSON_GetObjectItem(args, "supportsStartDebuggingRequest");
        if (supports_start_debugging && cJSON_IsBool(supports_start_debugging))
        {
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
    for (int i = 0; i < DAP_CAP_COUNT; i++)
    {
        cJSON_AddBoolToObject(capabilities, server_capabilities[i].name, server_capabilities[i].supported);
    }

    // Create and add exception filters
    cJSON *exceptionFilters = cJSON_CreateArray();
    if (exceptionFilters)
    {
        // Add all defined exception filters
        for (int i = 0; i < DAP_EXC_FILTER_COUNT; i++)
        {
            cJSON *filter = cJSON_CreateObject();
            if (filter)
            {
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
    if (server->client_capabilities.supportsANSIStyling)
    {
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


int handle_set_breakpoints(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!args || !response)
    {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    // Set command type
    server->current_command.type = DAP_CMD_SET_BREAKPOINTS;
    memset(&server->current_command.context.breakpoint, 0, sizeof(BreakpointCommandContext));

    // Parse source
    cJSON *source = cJSON_GetObjectItem(args, "source");
    if (!source)
    {
        set_response_error(response, "Missing source");
        return -1;
    }

    // Get source path and name
    cJSON *path = cJSON_GetObjectItem(source, "path");
    if (path && cJSON_IsString(path))
    {
        server->current_command.context.breakpoint.source_path = strdup(path->valuestring);
    }
    else
    {
        set_response_error(response, "Missing source path");
        return -1;
    }

    cJSON *name = cJSON_GetObjectItem(source, "name");
    if (name && cJSON_IsString(name))
    {
        server->current_command.context.breakpoint.source_name = strdup(name->valuestring);
    }

    // Check for sourceModified flag
    cJSON *source_modified = cJSON_GetObjectItem(args, "sourceModified");
    if (source_modified && cJSON_IsBool(source_modified))
    {
        server->current_command.context.breakpoint.source_modified = cJSON_IsTrue(source_modified);
    }

    // Parse breakpoints array
    cJSON *breakpoints = cJSON_GetObjectItem(args, "breakpoints");
    DAPBreakpoint *bp_array = NULL;
    int count = 0;

    if (breakpoints && cJSON_IsArray(breakpoints))
    {
        count = cJSON_GetArraySize(breakpoints);
        if (count > 0)
        {
            // Allocate array of DAPBreakpoint objects
            bp_array = malloc(count * sizeof(DAPBreakpoint));
            if (!bp_array)
            {
                cleanup_command_context(server);
                set_response_error(response, "Memory allocation failed");
                return -1;
            }

            // Parse each breakpoint
            for (int i = 0; i < count; i++)
            {
                cJSON *bp = cJSON_GetArrayItem(breakpoints, i);
                if (!bp)
                    continue;

                memset(&bp_array[i], 0, sizeof(DAPBreakpoint));

                // Required: line
                cJSON *line = cJSON_GetObjectItem(bp, "line");
                if (line && cJSON_IsNumber(line))
                {
                    bp_array[i].line = line->valueint;
                }

                // Optional: column
                cJSON *column = cJSON_GetObjectItem(bp, "column");
                if (column && cJSON_IsNumber(column))
                {
                    bp_array[i].column = column->valueint;
                }

                // Optional: condition
                cJSON *condition = cJSON_GetObjectItem(bp, "condition");
                if (condition && cJSON_IsString(condition))
                {
                    bp_array[i].condition = strdup(condition->valuestring);
                }

                // Optional: hitCondition
                cJSON *hit_condition = cJSON_GetObjectItem(bp, "hitCondition");
                if (hit_condition && cJSON_IsString(hit_condition))
                {
                    bp_array[i].hit_condition = strdup(hit_condition->valuestring);
                }

                // Optional: logMessage
                cJSON *log_message = cJSON_GetObjectItem(bp, "logMessage");
                if (log_message && cJSON_IsString(log_message))
                {
                    bp_array[i].log_message = strdup(log_message->valuestring);
                }

                // Set default verified state
                bp_array[i].verified = true;

                // Set source information for each breakpoint
                if (server->current_command.context.breakpoint.source_path)
                {
                    bp_array[i].source_path = strdup(server->current_command.context.breakpoint.source_path);
                }

                if (server->current_command.context.breakpoint.source_name)
                {
                    bp_array[i].source_name = strdup(server->current_command.context.breakpoint.source_name);
                }
            }

            // Store the breakpoints in the command context
            server->current_command.context.breakpoint.breakpoints = bp_array;
            server->current_command.context.breakpoint.breakpoint_count = count;
        }
    }
    else
    {
        // DAP spec allows this - it means clear all breakpoints for this source
        server->current_command.context.breakpoint.breakpoints = NULL;
        server->current_command.context.breakpoint.breakpoint_count = 0;
    }

    // Call implementation callback
    int result = 0;
    const DAPBreakpoint *result_breakpoints = server->current_command.context.breakpoint.breakpoints;
    int result_count = server->current_command.context.breakpoint.breakpoint_count;

    // Call the implementation - it will read from the context but not free anything

    result = dap_server_execute_callback(server, DAP_CMD_SET_BREAKPOINTS);

    // Create response from context after callback
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        // Free the breakpoints we allocated
        free_breakpoints_array(bp_array, count);

        cleanup_command_context(server);
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Create breakpoints array for response
    cJSON *response_breakpoints = cJSON_CreateArray();
    if (!response_breakpoints)
    {
        cJSON_Delete(body);

        // Free the breakpoints we allocated
        free_breakpoints_array(bp_array, count);

        cleanup_command_context(server);
        set_response_error(response, "Failed to create breakpoints array");
        return -1;
    }

    // Add each breakpoint to response (using the possibly updated values from the callback)
    for (int i = 0; i < result_count; i++)
    {
        const DAPBreakpoint *bp = &result_breakpoints[i];

        cJSON *response_bp = cJSON_CreateObject();
        if (!response_bp)
            continue;

        // Required fields
        cJSON_AddNumberToObject(response_bp, "id", i + 1);
        cJSON_AddBoolToObject(response_bp, "verified", bp->verified);
        cJSON_AddNumberToObject(response_bp, "line", bp->line);

        // Optional fields
        if (bp->column > 0)
        {
            cJSON_AddNumberToObject(response_bp, "column", bp->column);
        }

        if (bp->message)
        {
            cJSON_AddStringToObject(response_bp, "message", bp->message);
        }

        // Add source information
        if (bp->source_path)
        {
            cJSON *source_obj = cJSON_CreateObject();
            if (source_obj)
            {
                cJSON_AddStringToObject(source_obj, "path", bp->source_path);

                if (bp->source_name)
                {
                    cJSON_AddStringToObject(source_obj, "name", bp->source_name);
                }

                cJSON_AddItemToObject(response_bp, "source", source_obj);
            }
        }

        cJSON_AddItemToArray(response_breakpoints, response_bp);
    }

    cJSON_AddItemToObject(body, "breakpoints", response_breakpoints);
    set_response_success(response, body);

    // Always free the breakpoints array we allocated
    if (bp_array)
    {
        free_breakpoints_array(bp_array, count);
        // Clear the pointer to avoid double-free in cleanup_command_context
        if (server->current_command.context.breakpoint.breakpoints == bp_array)
        {
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
void free_breakpoints_array(const DAPBreakpoint *breakpoints, int count)
{
    if (!breakpoints || count <= 0)
    {
        return;
    }

    for (int i = 0; i < count; i++)
    {
        // Free any condition strings
        if (breakpoints[i].condition)
        {
            free((void *)breakpoints[i].condition);
        }

        if (breakpoints[i].hit_condition)
        {
            free((void *)breakpoints[i].hit_condition);
        }

        if (breakpoints[i].log_message)
        {
            free((void *)breakpoints[i].log_message);
        }

        if (breakpoints[i].message)
        {
            free((void *)breakpoints[i].message);
        }

        // Free the source object and its members
        if (breakpoints[i].source_path)
        {
            free((void *)breakpoints[i].source_path);
        }

        if (breakpoints[i].source_name)
        {
            free((void *)breakpoints[i].source_name);
        }
    }

    // Free the breakpoints array
    free((void *)breakpoints);
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


/*
{
  "command": "disassemble",
  "arguments": {
    "memoryReference": "0x1000",   // Required: memory address or register name (string)
    "offset": 0,                   // Optional: add/subtract bytes
    "instructionOffset": 0,        // Optional: relative instruction index
    "instructionCount": 32,        // Required: how many instructions to disassemble
    "resolveSymbols": true         // Optional: whether to show symbols
  }
}
*/

    // Parse required arguments - memoryReference
    cJSON *memory_reference = cJSON_GetObjectItem(args, "memoryReference");
    if (!memory_reference || !cJSON_IsString(memory_reference))
    {
        set_response_error(response, "Missing or invalid memoryReference");
        return -1;
    }

    // Convert memory reference from string to uint32_t    
    server->current_command.context.disassemble.memory_reference = (uint32_t)string_to_uint32(memory_reference->valuestring);
    
    // Parse optional arguments with defaults
    cJSON *offset_json = cJSON_GetObjectItem(args, "offset");
    if (offset_json && cJSON_IsNumber(offset_json))
    {
        server->current_command.context.disassemble.offset = (uint32_t)offset_json->valuedouble;
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

    /****************** CALLBACK ******************/
    int callback_result = dap_server_execute_callback(server, DAP_CMD_DISASSEMBLE);
    
    if (callback_result < 0)
    {
        DAP_SERVER_DEBUG_LOG("Disassemble implementation callback failed");
        set_response_error(response, "Disassemble implementation callback failed");
        return -1;
    }
    
    /****************** END CALLBACK ******************/

/*
{
  "instructions": [
    {
      "address": "0x1000",
      "instruction": "mov a, b",
      "symbol": "main"
    }
  ]
}
*/
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

    // Add instructions to the response
    for (int i = 0; i < server->current_command.context.disassemble.actual_instruction_count; i++)
    {

        DisassembleInstruction *instruction = &server->current_command.context.disassemble.instructions[i];

        cJSON *instruction_obj = cJSON_CreateObject();
        if (!instruction_obj)
            continue;

        if(instruction->address)
        {
            cJSON_AddStringToObject(instruction_obj, "address", instruction->address);
        }

        if (instruction->instruction)
        {
            cJSON_AddStringToObject(instruction_obj, "instruction", instruction->instruction);
        }

        if (instruction->symbol)
        {
            cJSON_AddStringToObject(instruction_obj, "symbol", instruction->symbol);
        }


        cJSON_AddItemToArray(instructions, instruction_obj);
    }


    // Add instructions array to body
    cJSON_AddItemToObject(body, "instructions", instructions);

    // Set response
    set_response_success(response, body);

    return 0;
}

/// @brief Handle the DAP "continue" command
/// @param server
/// @param args
/// @param response
/// @return
int handle_continue(DAPServer *server, cJSON *args, DAPResponse *response)
{
    (void)args; // Mark as unused
    if (!server->is_running || !server->attached)
    {
        set_response_error(response, "Debugger not running or attached");
        return -1;
    }

    // TODO: Analyse if we really need this check
    /* if (!server->debugger_state.has_stopped)
    {
        set_response_error(response, "Debugger not stopped");
        return -1;
    } */

    // Parse thread ID and single_thread flag
    int thread_id = 1; // Default to thread 1    
    if (args)
    {
        cJSON *thread_id_json = cJSON_GetObjectItem(args, "threadId");
        if (thread_id_json && cJSON_IsNumber(thread_id_json))
        {
            thread_id = thread_id_json->valueint;
        }
    }

    server->current_command.context.continue_cmd.thread_id = thread_id;    

    int callback_result = dap_server_execute_callback(server, DAP_CMD_CONTINUE);
    if (callback_result < 0)
    {
        DAP_SERVER_DEBUG_LOG("Continue implementation callback failed");
        set_response_error(response, "Continue implementation callback failed");
        return -1;
    }

    // Create success response
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    if (server->current_command.context.continue_cmd.all_threads_continue)
    {
        cJSON_AddBoolToObject(body, "allThreadsContinued", true);
    }


    set_response_success(response, body);
    // body is freed by set_response_success

    server->debugger_state.has_stopped = false;
    return 0;
}

int handleStepCommand(const char *command, DAPServer *server, cJSON *args, DAPResponse *response)
{
    DAPCommandType cmd_type = DAP_CMD_INVALID;

    // Determine which command type we're handling
    if (strcmp(command, "next") == 0)
    {
        cmd_type = DAP_CMD_NEXT;
    }
    else if (strcmp(command, "stepIn") == 0)
    {
        cmd_type = DAP_CMD_STEP_IN;
    }
    else if (strcmp(command, "stepOut") == 0)
    {
        cmd_type = DAP_CMD_STEP_OUT;
    }

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

    // Parse arguments and populate command context
    server->current_command.type = cmd_type;
    memset(&server->current_command.context.step, 0, sizeof(StepCommandContext));

    // Set defaults
    server->current_command.context.step.thread_id = 1; // Default to thread 1
    server->current_command.context.step.single_thread = false;
    server->current_command.context.step.granularity = DAP_STEP_GRANULARITY_STATEMENT; // Default granularity
    server->current_command.context.step.target_id = -1;                               // Not used for step next

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

    // Extract granularity if available and convert to enum
    cJSON *granularity_json = cJSON_GetObjectItem(args, "granularity");
    if (granularity_json && cJSON_IsString(granularity_json))
    {
        const char *granularity_str = granularity_json->valuestring;
        if (strcmp(granularity_str, "instruction") == 0)
        {
            server->current_command.context.step.granularity = DAP_STEP_GRANULARITY_INSTRUCTION;
        }
        else if (strcmp(granularity_str, "line") == 0)
        {
            server->current_command.context.step.granularity = DAP_STEP_GRANULARITY_LINE;
        }
        else
        {
            // Default to statement for any other value
            server->current_command.context.step.granularity = DAP_STEP_GRANULARITY_STATEMENT;
        }
    }

    // Extract targetId for stepIn if provided
    if (cmd_type == DAP_CMD_STEP_IN)
    {
        cJSON *target_id_json = cJSON_GetObjectItem(args, "targetId");
        if (target_id_json && cJSON_IsNumber(target_id_json))
        {
            server->current_command.context.step.target_id = target_id_json->valueint;
        }
    }

    // Call the implementation callback
    DAP_SERVER_DEBUG_LOG("Calling implementation callback for %s", command);
    int callback_result = dap_server_execute_callback(server, cmd_type);

    if (callback_result < 0)
    {
        DAP_SERVER_DEBUG_LOG("Callback failed");
        set_response_error(response, "Step implementation callback failed");
        return -1;
    }

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    cJSON_AddBoolToObject(body, "allThreadsStopped", !server->current_command.context.step.single_thread);

    // Set success response
    set_response_success(response, body);
    
    return 0;
}

int handle_next(DAPServer *server, cJSON *args, DAPResponse *response)
{

    return handleStepCommand("next", server, args, response);
}

int handle_step_in(DAPServer *server, cJSON *args, DAPResponse *response)
{

    return handleStepCommand("stepIn", server, args, response);
}

int handle_step_out(DAPServer *server, cJSON *args, DAPResponse *response)
{
    return handleStepCommand("stepOut", server, args, response);
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

    // Convert memory reference from string to uint32_t
    char *endptr = NULL;
    server->current_command.context.read_memory.memory_reference = (uint32_t)strtoul(memory_reference->valuestring, &endptr, 0);
    if (endptr == memory_reference->valuestring || *endptr != '\0')
    {
        set_response_error(response, "Invalid memory reference format");
        return -1;
    }

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
        server->current_command.context.read_memory.offset = (uint32_t)offset_json->valuedouble;
    }

    // Validate parameters
    if (server->current_command.context.read_memory.count < 0)
    {
        set_response_error(response, "Invalid count parameter (must be >=0)");
        return -1;
    }

    // Limit the count to 4096  
    if (server->current_command.context.read_memory.count > 4096)
    {
        server->current_command.context.read_memory.count = 4096;
    }

    /****************** CALLBACK ******************/
    int callback_result = dap_server_execute_callback(server, DAP_CMD_READ_MEMORY);


    if (callback_result < 0)
    {
        DAP_SERVER_DEBUG_LOG("readMemory implementation callback failed");
        set_response_error(response, "readMemory implementation callback failed");
        return -1;
    }
    /****************** END CALLBACK ******************/


    // Default implementation if no callback is registered
    // This will be a mock implementation that returns dummy data
    // Get the memory reference value directly (it's already a uint32_t)
    
    // Apply offset to address
    int address = server->current_command.context.read_memory.memory_reference + server->current_command.context.read_memory.offset;

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Format address as a string (per DAP spec)
    char address_str[32];
    snprintf(address_str, sizeof(address_str), "%06o", address);
    cJSON_AddStringToObject(body, "address", address_str);


    if (server->current_command.context.read_memory.base64_data)
    {
        cJSON_AddStringToObject(body, "data", server->current_command.context.read_memory.base64_data);
        free(server->current_command.context.read_memory.base64_data);
        server->current_command.context.read_memory.base64_data = NULL;
    }

    // Add unreadableBytes = 0 (all bytes were readable)
    cJSON_AddNumberToObject(body, "unreadableBytes", server->current_command.context.read_memory.unreadable_bytes);

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

    // Convert memory reference from string to uint32_t
    char *endptr = NULL;
    server->current_command.context.write_memory.memory_reference = (uint32_t)strtoul(memory_reference->valuestring, &endptr, 0);
    if (endptr == memory_reference->valuestring || *endptr != '\0')
    {
        set_response_error(response, "Invalid memory reference format");
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
    if (!server->current_command.context.write_memory.data)
    {
        set_response_error(response, "Failed to allocate memory for data");
        return -1;
    }

    // Parse optional offset parameter (defaults to 0)
    server->current_command.context.write_memory.offset = 0;
    cJSON *offset_json = cJSON_GetObjectItem(args, "offset");
    if (offset_json && cJSON_IsNumber(offset_json))
    {
        server->current_command.context.write_memory.offset = (uint32_t)offset_json->valuedouble;
    }

    // Parse optional allowPartial parameter (defaults to false)
    server->current_command.context.write_memory.allow_partial = false;
    cJSON *allow_partial_json = cJSON_GetObjectItem(args, "allowPartial");
    if (allow_partial_json && cJSON_IsBool(allow_partial_json))
    {
        server->current_command.context.write_memory.allow_partial = cJSON_IsTrue(allow_partial_json);
    }

    // Call the implementation callback if registered

    int callback_result = dap_server_execute_callback(server, DAP_CMD_WRITE_MEMORY);

    if (callback_result < 0)
    {
        DAP_SERVER_DEBUG_LOG("writeMemory implementation callback failed");
        set_response_error(response, "writeMemory implementation callback failed");
        return -1;
    }

    // generate a success response
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    cJSON_AddNumberToObject(body, "bytesWritten", server->current_command.context.write_memory.bytes_written);

    // Set success response
    set_response_success(response, body);

    // body is freed by set_response_success
    // Free the allocated memory for data
    if (server->current_command.context.write_memory.data)
    {
        free(server->current_command.context.write_memory.data);
        server->current_command.context.write_memory.data = NULL;
    }

    return 0;
}

// Create and send empty response
#define SEND_EMPTY_SUCCESS_RESPONSE()                                           \
    do                                                                          \
    {                                                                           \
        cJSON *empty_body = cJSON_CreateObject();                               \
        if (!empty_body)                                                        \
        {                                                                       \
            response->success = false;                                          \
            response->error_message = strdup("Failed to create response body"); \
            return 0;                                                           \
        }                                                                       \
        char *body_str = cJSON_PrintUnformatted(empty_body);                    \
        cJSON_Delete(empty_body);                                               \
        if (!body_str)                                                          \
        {                                                                       \
            response->success = false;                                          \
            response->error_message = strdup("Failed to format response body"); \
            return 0;                                                           \
        }                                                                       \
        response->success = true;                                               \
        response->data = body_str;                                              \
        return 0;                                                               \
    } while (0)

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

    // Set the command type for the callback
    server->current_command.type = DAP_CMD_CONFIGURATION_DONE;

    // Call the implementation callback if registered
    int callback_result = dap_server_execute_callback(server, DAP_CMD_CONFIGURATION_DONE);
    if (callback_result < 0) {        
        set_response_error(response, "configurationDone implementation callback failed");
        return -1;
    }

    // Set success response - no body needed as per spec        
    response->data = NULL;
    set_response_success(response, NULL);

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
    if (server->debugger_state.program_path)
    {
        free((void *)server->debugger_state.program_path);
        server->debugger_state.program_path = NULL;
    }

    if (server->debugger_state.source_path)
    {
        free((void *)server->debugger_state.source_path);
        server->debugger_state.source_path = NULL;
    }

    if (server->debugger_state.map_path)
    {
        free((void *)server->debugger_state.map_path);
        server->debugger_state.map_path = NULL;
    }

    if (server->debugger_state.working_directory)
    {
        free((void *)server->debugger_state.working_directory);
        server->debugger_state.working_directory = NULL;
    }

    // Free any previous command line arguments
    if (server->debugger_state.args)
    {
        for (int i = 0; i < server->debugger_state.args_count; i++)
        {
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
    const char *value_str = program_json->valuestring;
    if (!value_str)
    {
        set_response_error(response, "Program path is null");
        return -1;
    }

    char *program_path = strdup(value_str);
    if (!program_path)
    {
        set_response_error(response, "Failed to allocate memory for program path");
        return -1;
    }
    server->debugger_state.program_path = program_path;
    DAP_SERVER_DEBUG_LOG("Launch program path: %s", program_path);

    // Optional field - source file (default code file to display)
    cJSON *source_file_json = cJSON_GetObjectItem(args, "sourceFile");
    if (source_file_json && cJSON_IsString(source_file_json) && source_file_json->valuestring)
    {
        const char *source_str = source_file_json->valuestring;
        char *source_path = strdup(source_str);
        if (!source_path)
        {
            set_response_error(response, "Failed to allocate memory for source path");
            goto cleanup;
        }
        server->debugger_state.source_path = source_path;
        DAP_SERVER_DEBUG_LOG("Source file: %s", source_path);
    }
    else
    {
        // Make sure the source_path field is NULL to avoid dangling pointers
        server->debugger_state.source_path = NULL;
        DAP_SERVER_DEBUG_LOG("Source file: (not specified)");
    }

    // Optional field - map file (for address to source mapping)
    cJSON *map_file_json = cJSON_GetObjectItem(args, "mapFile");
    if (map_file_json && cJSON_IsString(map_file_json) && map_file_json->valuestring)
    {
        const char *map_str = map_file_json->valuestring;
        char *map_path = strdup(map_str);
        if (!map_path)
        {
            set_response_error(response, "Failed to allocate memory for map file path");
            goto cleanup;
        }
        server->debugger_state.map_path = map_path;
        DAP_SERVER_DEBUG_LOG("Map file: %s", map_path);
    }
    else
    {
        // Make sure the map_path field is NULL to avoid dangling pointers
        server->debugger_state.map_path = NULL;
        DAP_SERVER_DEBUG_LOG("Map file: (not specified)");
    }

    // Optional field - working directory
    cJSON *cwd_json = cJSON_GetObjectItem(args, "cwd");
    if (cwd_json && cJSON_IsString(cwd_json) && cwd_json->valuestring)
    {
        const char *cwd_str = cwd_json->valuestring;
        char *working_directory = strdup(cwd_str);
        if (!working_directory)
        {
            set_response_error(response, "Failed to allocate memory for working directory");
            goto cleanup;
        }
        server->debugger_state.working_directory = working_directory;
        DAP_SERVER_DEBUG_LOG("Working directory: %s", working_directory);

        // Change directory if specified (this could be moved to the implementation callback)
        if (chdir(cwd_str) != 0)
        {
            DAP_SERVER_DEBUG_LOG("Failed to change working directory: %s", strerror(errno));
            // Continue despite failure - the implementation can handle this
        }
    }
    else
    {
        //TODO: Maybe remove launch context ???
        // Make sure the launch context fields are NULL to avoid dangling pointers 
        server->current_command.context.launch.working_directory = NULL;
        server->current_command.context.launch.program_path = NULL;
        server->current_command.context.launch.source_path = NULL;
        server->current_command.context.launch.map_path = NULL;        

        DAP_SERVER_DEBUG_LOG("Working directory: (not specified)");
    }

    // Optional field - noDebug flag
    cJSON *no_debug_json = cJSON_GetObjectItem(args, "noDebug");
    if (no_debug_json && cJSON_IsBool(no_debug_json))
    {
        server->debugger_state.no_debug = cJSON_IsTrue(no_debug_json);
        DAP_SERVER_DEBUG_LOG("noDebug: %s", server->debugger_state.no_debug ? "true" : "false");
    }

    // Optional field - stopOnEntry flag
    cJSON *stop_entry_json = cJSON_GetObjectItem(args, "stopOnEntry");
    if (stop_entry_json && cJSON_IsBool(stop_entry_json))
    {
        server->debugger_state.stop_at_entry = cJSON_IsTrue(stop_entry_json);
        DAP_SERVER_DEBUG_LOG("stopOnEntry: %s", server->debugger_state.stop_at_entry ? "true" : "false");
    }

    // Optional field - args (command line arguments)
    cJSON *args_json = cJSON_GetObjectItem(args, "args");
    if (args_json && cJSON_IsArray(args_json))
    {
        int args_count = cJSON_GetArraySize(args_json);
        if (args_count > 0)
        {
            // Allocate array of char* pointers
            char **cmd_args = calloc(args_count + 1, sizeof(char *)); // +1 for NULL terminator
            if (!cmd_args)
            {
                set_response_error(response, "Failed to allocate memory for command line arguments");
                goto cleanup;
            }

            // Copy each argument
            for (int i = 0; i < args_count; i++)
            {
                cJSON *arg = cJSON_GetArrayItem(args_json, i);
                if (arg && cJSON_IsString(arg) && arg->valuestring)
                {
                    cmd_args[i] = strdup(arg->valuestring);
                    if (!cmd_args[i])
                    {
                        // Free previously allocated args
                        for (int j = 0; j < i; j++)
                        {
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
    int callback_result = dap_server_execute_callback(server, DAP_CMD_LAUNCH);
    if (callback_result < 0)
    {
        DAP_SERVER_DEBUG_LOG("Launch callback returned error: %d", callback_result);
        return -1;
    }

    // TODO: Evaluate all fields for the response and if STOP event should be sent (as its probably handled elsewhere)

    // Set debugger state    
    server->attached = true;
    server->debugger_state.has_stopped = true;
    server->debugger_state.current_thread_id = 1; // make sure we have a thread id

    // Send default events if no callback is registered
    DAP_SERVER_DEBUG_LOG("Sending stopped event after launch response");
    // Stopped at entry point (program start).
    dap_server_send_stopped_event(server, "entry", NULL);

    // Per DAP spec and Microsoft's implementation, a launch response should be minimal with no body
    if (callback_result >= 0)
    {
        set_response_success(response, NULL);
        if (server->debugger_state.program_path)
        {
            DAP_SERVER_DEBUG_LOG("Launch response prepared for program: %s",
                                 server->debugger_state.program_path);
        }
        else
        {
            DAP_SERVER_DEBUG_LOG("Launch response prepared (no program path)");
        }
    }
    else
    {
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
    server->attached = true;
    server->debugger_state.has_stopped = true;

    // Create a proper JSON object instead of using strdup
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        response->success = false;
        response->error_message = strdup("Failed to create response body");
        return 0;
    }

    set_response_success(response, body);
    // body is freed by set_response_success
    return 0;
}

int handle_disconnect(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server || !response)
    {
        set_response_error(response, "Invalid server or response");
        return -1;
    }

    // Initialize the command context for disconnect
    server->current_command.type = DAP_CMD_DISCONNECT;
    memset(&server->current_command.context.disconnect, 0, sizeof(DisconnectCommandContext));

    // Parse arguments if present
    if (args)
    {
        // Check if terminateDebuggee option is set
        cJSON *terminate_json = cJSON_GetObjectItem(args, "terminateDebuggee");
        if (terminate_json && cJSON_IsBool(terminate_json))
        {
            server->current_command.context.disconnect.terminate_debuggee = cJSON_IsTrue(terminate_json);
            DAP_SERVER_DEBUG_LOG("Disconnect with terminateDebuggee: %s",
                                 server->current_command.context.disconnect.terminate_debuggee ? "true" : "false");
        }

        // Check if suspendDebuggee option is set (available in newer DAP versions)
        cJSON *suspend_json = cJSON_GetObjectItem(args, "suspendDebuggee");
        if (suspend_json && cJSON_IsBool(suspend_json))
        {
            server->current_command.context.disconnect.suspend_debuggee = cJSON_IsTrue(suspend_json);
            DAP_SERVER_DEBUG_LOG("Disconnect with suspendDebuggee: %s",
                                 server->current_command.context.disconnect.suspend_debuggee ? "true" : "false");
        }

        // Check if restart option is set
        cJSON *restart_json = cJSON_GetObjectItem(args, "restart");
        if (restart_json && cJSON_IsBool(restart_json))
        {
            server->current_command.context.disconnect.restart = cJSON_IsTrue(restart_json);
            DAP_SERVER_DEBUG_LOG("Disconnect with restart: %s",
                                 server->current_command.context.disconnect.restart ? "true" : "false");
        }
    }

    // Call the implementation callback if registered

    int callback_result = dap_server_execute_callback(server, DAP_CMD_DISCONNECT);
    if (callback_result < 0)
    {
        DAP_SERVER_DEBUG_LOG("Disconnect implementation callback failed with code %d", callback_result);
    }
    

    // Reset server state
    server->attached = false;

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Set response according to callback result
    if (callback_result >= 0)
    {
        set_response_success(response, body);
    }
    else
    {
        cJSON_Delete(body); // Must delete body as we're not passing it to set_response_error
        set_response_error(response, "Disconnect command failed");
    }

    // Note: Context resources will be cleaned up by cleanup_command_context

    return 0;
}

/**
 * @brief Handles the DAP 'stackTrace' request
 *
 * The stackTrace request returns a list of stack frames for a given thread.
 * This implementation supports:
 *  - A single thread model (thread ID 1)
 *  - Source file mapping
 *  - Start frame offset and frame count limits
 *  - Custom format options
 *
 * This handler delegates the actual stack trace generation to a registered callback.
 * If no callback is registered, the command fails with an error.
 *
 * @param server DAP server instance
 * @param args Command arguments (threadId, startFrame, levels, format)
 * @param response Response to fill with stack frames
 * @return int 0 on success, non-zero on failure
 */
int handle_stack_trace(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server || !args || !response)
    {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    if (!server->is_running || !server->attached)
    {
        set_response_error(response, "Debugger is not running or not attached");
        return -1;
    }

    // Initialize the command context for stackTrace
    server->current_command.type = DAP_CMD_STACK_TRACE;
    memset(&server->current_command.context.stack_trace, 0, sizeof(StackTraceCommandContext));

    // Parse arguments
    cJSON *thread_id_json = cJSON_GetObjectItem(args, "threadId");
    int thread_id = 1; // Default to thread 1

    if (thread_id_json && cJSON_IsNumber(thread_id_json))
    {
        thread_id = thread_id_json->valueint;
    }

    // Validate thread ID - we only support thread 1 in this implementation
    if (thread_id != 1)
    {
        set_response_error(response, "Invalid thread ID - only thread 1 is supported");
        return -1;
    }

    cJSON *start_frame_json = cJSON_GetObjectItem(args, "startFrame");
    if (start_frame_json && cJSON_IsNumber(start_frame_json))
    {
        server->current_command.context.stack_trace.start_frame = start_frame_json->valueint;
    }
    else
    {
        server->current_command.context.stack_trace.start_frame = 0; // Default to frame 0
    }

    cJSON *levels_json = cJSON_GetObjectItem(args, "levels");
    if (levels_json && cJSON_IsNumber(levels_json))
    {
        server->current_command.context.stack_trace.levels = levels_json->valueint;
    }
    else
    {
        server->current_command.context.stack_trace.levels = 1; // Default to 1 level
    }

    // Parse format options into our StackTraceFormat structure
    StackTraceFormat *format = &server->current_command.context.stack_trace.format;

    // Initialize with defaults (all false)
    memset(format, 0, sizeof(StackTraceFormat));

    // Format is optional
    cJSON *format_json = cJSON_GetObjectItem(args, "format");
    if (format_json && cJSON_IsObject(format_json))
    {
        // Parse individual format options
        cJSON *parameters = cJSON_GetObjectItem(format_json, "parameters");
        if (parameters && cJSON_IsBool(parameters))
        {
            format->parameters = cJSON_IsTrue(parameters);
        }

        cJSON *parameter_types = cJSON_GetObjectItem(format_json, "parameterTypes");
        if (parameter_types && cJSON_IsBool(parameter_types))
        {
            format->parameter_types = cJSON_IsTrue(parameter_types);
        }

        cJSON *parameter_names = cJSON_GetObjectItem(format_json, "parameterNames");
        if (parameter_names && cJSON_IsBool(parameter_names))
        {
            format->parameter_names = cJSON_IsTrue(parameter_names);
        }

        cJSON *parameter_values = cJSON_GetObjectItem(format_json, "parameterValues");
        if (parameter_values && cJSON_IsBool(parameter_values))
        {
            format->parameter_values = cJSON_IsTrue(parameter_values);
        }

        cJSON *line = cJSON_GetObjectItem(format_json, "line");
        if (line && cJSON_IsBool(line))
        {
            format->line = cJSON_IsTrue(line);
        }

        cJSON *module = cJSON_GetObjectItem(format_json, "module");
        if (module && cJSON_IsBool(module))
        {
            format->module = cJSON_IsTrue(module);
        }

        cJSON *include_all = cJSON_GetObjectItem(format_json, "includeAll");
        if (include_all && cJSON_IsBool(include_all))
        {
            format->include_all = cJSON_IsTrue(include_all);
        }
    }

    // Validate start_frame and levels
    if (server->current_command.context.stack_trace.start_frame < 0 ||
        server->current_command.context.stack_trace.levels < 1)
    {
        set_response_error(response, "Invalid startFrame or levels parameter");
        return -1;
    }

    // Call implementation callback if registered
    int callback_result = dap_server_execute_callback(server, DAP_CMD_STACK_TRACE);

    if (callback_result < 0)
    {
        DAP_SERVER_DEBUG_LOG("StackTrace implementation callback failed");
        set_response_error(response, "StackTrace implementation callback failed");
        return -1;
    }

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
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

    // FInd the longest frame name
    int max_frame_name_len = 0;
    for (int i = 0; i < server->current_command.context.stack_trace.frame_count; i++)
    {
        DAPStackFrame *frame_data = &server->current_command.context.stack_trace.frames[i];
        if (frame_data->name && (int)strlen(frame_data->name) > max_frame_name_len)
        {
            max_frame_name_len = strlen(frame_data->name);
        }
    }

    // Add frames from the command context
    for (int i = 0; i < server->current_command.context.stack_trace.frame_count; i++)
    {
        DAPStackFrame *frame_data = &server->current_command.context.stack_trace.frames[i];
        
        // Create frame object
        cJSON *frame = cJSON_CreateObject();
        if (!frame)
        {
            cJSON_Delete(body);
            cJSON_Delete(frames);
            set_response_error(response, "Failed to create frame object");
            return -1;
        }

        char frame_name[50];
        uint32_t offset = 0;
        if (frame_data->valid_symbol)
        {
            offset = frame_data->instruction_pointer_reference - frame_data->symbol_entry_point; 
        }

        snprintf(frame_name, sizeof(frame_name), "%-*s +%d @%05o", max_frame_name_len, frame_data->name, offset,frame_data->instruction_pointer_reference );

        
        // Add required properties according to the DAP spec
        cJSON_AddNumberToObject(frame, "id", frame_data->id);
        cJSON_AddStringToObject(frame, "name", frame_name);
        cJSON_AddNumberToObject(frame, "line", frame_data->line);
        cJSON_AddNumberToObject(frame, "column", frame_data->column);

        // Add optional source information if available
        if (frame_data->source_path || frame_data->source_name)
        {
            cJSON *source = cJSON_CreateObject();
            if (source)
            {
                if (frame_data->source_path)
                {
                    cJSON_AddStringToObject(source, "path", frame_data->source_path);
                }

                if (frame_data->source_name)
                {
                    cJSON_AddStringToObject(source, "name", frame_data->source_name);
                }
                else if (frame_data->source_path)
                {
                    // Extract filename from path if name not provided
                    const char *name = strrchr(frame_data->source_path, '/');
                    if (name)
                    {
                        cJSON_AddStringToObject(source, "name", name + 1);
                    }
                }

                cJSON_AddItemToObject(frame, "source", source);
            }
        }

        // Add optional end line/column if available
        if (frame_data->end_line > 0)
        {
            cJSON_AddNumberToObject(frame, "endLine", frame_data->end_line);
        }
        if (frame_data->end_column > 0)
        {
            cJSON_AddNumberToObject(frame, "endColumn", frame_data->end_column);
        }

        // Add optional instruction pointer reference if available
        if (frame_data->instruction_pointer_reference >= 0)
        {
            char ref_str[32];
            snprintf(ref_str, sizeof(ref_str), "0x%x", frame_data->instruction_pointer_reference);
            cJSON_AddStringToObject(frame, "instructionPointerReference", ref_str);
        }

        // Add optional module ID if available
        if (frame_data->module_id)
        {
            cJSON_AddStringToObject(frame, "moduleId", frame_data->module_id);
        }

        // Add optional presentation hint if available
        if (frame_data->presentation_hint != DAP_FRAME_PRESENTATION_NORMAL)
        {
            const char *hint = "normal";
            switch (frame_data->presentation_hint)
            {
                case DAP_FRAME_PRESENTATION_LABEL:
                    hint = "label";
                    break;
                case DAP_FRAME_PRESENTATION_SUBTLE:
                    hint = "subtle";
                    break;
                case DAP_FRAME_PRESENTATION_NORMAL:
                    hint = "normal";
                    break;
            }
            cJSON_AddStringToObject(frame, "presentationHint", hint);
        }

        // Add optional canRestart flag if available
        if (frame_data->can_restart)
        {
            cJSON_AddBoolToObject(frame, "canRestart", true);
        }

        // Add frame to array
        cJSON_AddItemToArray(frames, frame);
    }

    // Add frames array to body
    cJSON_AddItemToObject(body, "stackFrames", frames);

    // Add totalFrames property
    cJSON_AddNumberToObject(body, "totalFrames", server->current_command.context.stack_trace.total_frames);

    // Set response
    set_response_success(response, body);

    return 0;
}

/// @brief Handle the DAP 'scopes' request
/// @param server
/// @param args
/// @param response
/// @return
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

    // Initialize the scopes fields
    server->current_command.context.scopes.scopes = NULL;
    server->current_command.context.scopes.scope_count = 0;

    int result = dap_server_execute_callback(server, DAP_CMD_SCOPES);
    if (result == 0)
    {
        // Callback succeeded - check if it populated the scopes
        if (server->current_command.context.scopes.scopes != NULL &&
            server->current_command.context.scopes.scope_count > 0)
        {
            // The callback populated the scopes, create a response from them
            cJSON *body = cJSON_CreateObject();
            if (!body)
            {
                // Clean up allocated scopes
                DAPScope *scopes = server->current_command.context.scopes.scopes;
                int scope_count = server->current_command.context.scopes.scope_count;
                for (int i = 0; i < scope_count; i++)
                {
                    free(scopes[i].name);
                    if (scopes[i].source_path)
                        free(scopes[i].source_path);
                }
                free(scopes);

                set_response_error(response, "Failed to create response body");
                return -1;
            }

            // Create scopes array
            cJSON *scopes_array = cJSON_CreateArray();
            if (!scopes_array)
            {
                cJSON_Delete(body);

                // Clean up allocated scopes
                DAPScope *scopes = server->current_command.context.scopes.scopes;
                int scope_count = server->current_command.context.scopes.scope_count;
                for (int i = 0; i < scope_count; i++)
                {
                    free(scopes[i].name);
                    if (scopes[i].source_path)
                        free(scopes[i].source_path);
                }
                free(scopes);

                set_response_error(response, "Failed to create scopes array");
                return -1;
            }

            // Add each scope to the array
            DAPScope *scopes = server->current_command.context.scopes.scopes;
            int scope_count = server->current_command.context.scopes.scope_count;

            for (int i = 0; i < scope_count; i++)
            {
                cJSON *scope_obj = cJSON_CreateObject();
                if (!scope_obj)
                    continue;

                cJSON_AddStringToObject(scope_obj, "name", scopes[i].name);
                cJSON_AddNumberToObject(scope_obj, "variablesReference", scopes[i].variables_reference);
                cJSON_AddNumberToObject(scope_obj, "namedVariables", scopes[i].named_variables);
                cJSON_AddNumberToObject(scope_obj, "indexedVariables", scopes[i].indexed_variables);
                cJSON_AddBoolToObject(scope_obj, "expensive", scopes[i].expensive);

                // Add presentation hints based on scope name
                if (scopes[i].name != NULL)
                {
                    if (strcmp(scopes[i].name, "Locals") == 0)
                    {
                        cJSON_AddStringToObject(scope_obj, "presentationHint", "locals");
                    }
                    else if (strcmp(scopes[i].name, "CPU Registers") == 0)
                    {
                        cJSON_AddStringToObject(scope_obj, "presentationHint", "registers");
                    }
                }

                cJSON_AddItemToArray(scopes_array, scope_obj);
            }

            cJSON_AddItemToObject(body, "scopes", scopes_array);
            set_response_success(response, body);

            // Clean up allocated scopes
            for (int i = 0; i < scope_count; i++)
            {
                free(scopes[i].name);
                if (scopes[i].source_path)
                    free(scopes[i].source_path);
            }
            free(scopes);

            // Clear the context
            server->current_command.context.scopes.scopes = NULL;
            server->current_command.context.scopes.scope_count = 0;

            return 0;
        }
    }
    else
    {
        // Callback failed - set error response
        set_response_error(response, "Scopes callback failed");
        return -1;
    }
    return 0;
}


FormatOptions parse_format_options(cJSON *format) {
    FormatOptions opts = {0}; // All flags default to 0

    if (!cJSON_IsObject(format)) return opts;

    if (cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(format, "hex")))
        opts.hex = cJSON_IsTrue(cJSON_GetObjectItem(format, "hex"));

    if (cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(format, "decimal")))
        opts.decimal = cJSON_IsTrue(cJSON_GetObjectItem(format, "decimal"));

    if (cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(format, "binary")))
        opts.binary = cJSON_IsTrue(cJSON_GetObjectItem(format, "binary"));

    if (cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(format, "octal")))
        opts.octal = cJSON_IsTrue(cJSON_GetObjectItem(format, "octal"));

    if (cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(format, "showHex")))
        opts.showHex = cJSON_IsTrue(cJSON_GetObjectItem(format, "showHex"));

    if (cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(format, "variableType")))
        opts.variableType = cJSON_IsTrue(cJSON_GetObjectItem(format, "variableType"));

    if (cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(format, "includePointer")))
        opts.includePointer = cJSON_IsTrue(cJSON_GetObjectItem(format, "includePointer"));

    if (cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(format, "showRawString")))
        opts.showRawString = cJSON_IsTrue(cJSON_GetObjectItem(format, "showRawString"));

    return opts;
}


int handle_variables(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server || !args || !response)
    {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    // Get the variables reference from the args (Required)
    cJSON *vars_ref_json = cJSON_GetObjectItem(args, "variablesReference");
    if (!vars_ref_json || !cJSON_IsNumber(vars_ref_json))
    {
        set_response_error(response, "Missing or invalid variablesReference");
        return -1;
    }

    int ref = vars_ref_json->valueint;

    // Initialize the command context for variables
    server->current_command.type = DAP_CMD_VARIABLES;
    server->current_command.context.variables.variables_reference = ref;
    server->current_command.context.variables.filter = DAP_VARIABLE_FILTER_NONE;

    // Parse optional filter field (Optional)
    cJSON *filter_json = cJSON_GetObjectItem(args, "filter");
    if (filter_json && cJSON_IsString(filter_json))
    {
        const char *filter = filter_json->valuestring;
        if (strcmp(filter, "indexed") == 0)
        {
            server->current_command.context.variables.filter = DAP_VARIABLE_FILTER_INDEXED;
        }
        else if (strcmp(filter, "named") == 0)
        {
            server->current_command.context.variables.filter = DAP_VARIABLE_FILTER_NAMED;
        }
        else 
        {
            server->current_command.context.variables.filter = DAP_VARIABLE_FILTER_INVALID; // TODO: Add error handling
            return -1;
        }
    }

    // Parse optional start and count for paging (Optional)
    cJSON *start_json = cJSON_GetObjectItem(args, "start");
    if (start_json && cJSON_IsNumber(start_json))
    {
        server->current_command.context.variables.start = start_json->valueint;
    }

    // Parse optional count for paging (Optional)
    cJSON *count_json = cJSON_GetObjectItem(args, "count");
    if (count_json && cJSON_IsNumber(count_json))
    {
        server->current_command.context.variables.count = count_json->valueint;
    }

    // Parse optional format field (Optional)
    cJSON *format_json = cJSON_GetObjectItem(args, "format");
    server->current_command.context.variables.format_options = parse_format_options(format_json);


    /********************************************************************/
    // Call the implementation callback
    int result = dap_server_execute_callback(server, DAP_CMD_VARIABLES);
    if (result != 0)
    {
        set_response_error(response, "Variables callback failed");
        return -1;
    }
    /********************************************************************/

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        cleanup_command_context(server);
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Add variables array to response
    cJSON *variables_array = cJSON_CreateArray();
    if (!variables_array)
    {
        cJSON_Delete(body);
        cleanup_command_context(server);
        set_response_error(response, "Failed to create variables array");
        return -1;
    }

    // Add each variable to the array
    for (int i = 0; i < server->current_command.context.variables.variable_count; i++)
    {
        DAPVariable *var = &server->current_command.context.variables.variable_array[i];
        cJSON *var_obj = cJSON_CreateObject();
        if (!var_obj)
        {
            continue;
        }

        // Add required fields
        cJSON_AddStringToObject(var_obj, "name", var->name ? var->name : "UNKNOWN");
        cJSON_AddStringToObject(var_obj, "value", var->value ? var->value : "UNKNOWN");

        // Add optional fields if available
        if (var->type)
        {
            cJSON_AddStringToObject(var_obj, "type", var->type);
        }


        // variablesReference is an Required field!
        cJSON_AddNumberToObject(var_obj, "variablesReference", var->variables_reference);

        // namedVariables is an optional field
        if (var->named_variables > 0)
        {
            cJSON_AddNumberToObject(var_obj, "namedVariables", var->named_variables);
        }

        // indexedVariables is an optional field
        if (var->indexed_variables > 0)
        {
            cJSON_AddNumberToObject(var_obj, "indexedVariables", var->indexed_variables);
        }

        // evaluateName is an optional field
        if (var->evaluate_name)
        {
            cJSON_AddStringToObject(var_obj, "evaluateName", var->evaluate_name);
        }

        // Add presentation hint if available
        if (var->presentation_hint.kind != DAP_VARIABLE_KIND_NONE || var->presentation_hint.visibility != DAP_VARIABLE_VISIBILITY_NONE || var->presentation_hint.attributes != DAP_VARIABLE_ATTR_NONE)
        {
            cJSON *hint_obj = cJSON_CreateObject();
            if (hint_obj)
            {
                if (var->presentation_hint.kind != DAP_VARIABLE_KIND_NONE)
                {
                    const char *kind_str = NULL;
                    switch (var->presentation_hint.kind)
                    {
                        case DAP_VARIABLE_KIND_NONE:
                            // No kind specified, skip adding kind to hint
                            break;
                        case DAP_VARIABLE_KIND_PROPERTY:
                            kind_str = "property";
                            break;
                        case DAP_VARIABLE_KIND_METHOD:
                            kind_str = "method";
                            break;
                        case DAP_VARIABLE_KIND_CLASS:
                            kind_str = "class";
                            break;
                        case DAP_VARIABLE_KIND_DATA:
                            kind_str = "data";
                            break;
                        case DAP_VARIABLE_KIND_EVENT:
                            kind_str = "event";
                            break;
                        case DAP_VARIABLE_KIND_BASE_CLASS:
                            kind_str = "baseClass";
                            break;
                        case DAP_VARIABLE_KIND_INNER_CLASS:
                            kind_str = "innerClass";
                            break;
                        case DAP_VARIABLE_KIND_INTERFACE:
                            kind_str = "interface";
                            break;
                        case DAP_VARIABLE_KIND_MOST_DERIVED:
                            kind_str = "mostDerived";
                            break;
                        case DAP_VARIABLE_KIND_VIRTUAL:
                            kind_str = "virtual";
                            break;
                        case DAP_VARIABLE_KIND_DATABREAKPOINT:
                            kind_str = "dataBreakpoint";
                            break;
                    }
                    if (kind_str)
                    {
                        cJSON_AddStringToObject(hint_obj, "kind", kind_str);
                    }
                }

                if (var->presentation_hint.visibility != DAP_VARIABLE_VISIBILITY_NONE)
                {
                    const char *visibility_str = NULL;
                    switch (var->presentation_hint.visibility)
                    {
                        case DAP_VARIABLE_VISIBILITY_NONE:
                            // No visibility specified, skip adding visibility to hint
                            break;
                        case DAP_VARIABLE_VISIBILITY_PUBLIC:
                            visibility_str = "public";
                            break;
                        case DAP_VARIABLE_VISIBILITY_PRIVATE:
                            visibility_str = "private";
                            break;
                        case DAP_VARIABLE_VISIBILITY_PROTECTED:
                            visibility_str = "protected";
                            break;
                        default:
                            // Invalid visibility, skip adding visibility to hint
                            DAP_SERVER_DEBUG_LOG("Invalid visibility: %d", var->presentation_hint.visibility);
                            break;
                    }
                    if (visibility_str)
                    {
                        cJSON_AddStringToObject(hint_obj, "visibility", visibility_str);
                    }
                }

                if (var->presentation_hint.attributes != 0)
                {
                    cJSON *attributes_array = cJSON_CreateArray();
                    if (attributes_array)
                    {
                        if (var->presentation_hint.attributes & DAP_VARIABLE_ATTR_STATIC)
                            cJSON_AddItemToArray(attributes_array, cJSON_CreateString("static"));
                        if (var->presentation_hint.attributes & DAP_VARIABLE_ATTR_CONSTANT)
                            cJSON_AddItemToArray(attributes_array, cJSON_CreateString("constant"));
                        if (var->presentation_hint.attributes & DAP_VARIABLE_ATTR_READONLY)
                            cJSON_AddItemToArray(attributes_array, cJSON_CreateString("readOnly"));
                        if (var->presentation_hint.attributes & DAP_VARIABLE_ATTR_RAWSTRING)
                            cJSON_AddItemToArray(attributes_array, cJSON_CreateString("rawString"));
                        if (var->presentation_hint.attributes & DAP_VARIABLE_ATTR_HASOBJECTID)
                            cJSON_AddItemToArray(attributes_array, cJSON_CreateString("hasObjectId"));
                        if (var->presentation_hint.attributes & DAP_VARIABLE_ATTR_CANHAVEOBJECTID)
                            cJSON_AddItemToArray(attributes_array, cJSON_CreateString("canHaveObjectId"));
                        if (var->presentation_hint.attributes & DAP_VARIABLE_ATTR_HASSIDEEFFECTS)
                            cJSON_AddItemToArray(attributes_array, cJSON_CreateString("hasSideEffects"));
                        if (var->presentation_hint.attributes & DAP_VARIABLE_ATTR_HASDATABREAKPOINT)
                            cJSON_AddItemToArray(attributes_array, cJSON_CreateString("hasDataBreakpoint"));

                            
                        cJSON_AddItemToObject(hint_obj, "attributes", attributes_array);
                    }
                }

                cJSON_AddItemToObject(var_obj, "presentationHint", hint_obj);
            }

        }

        cJSON_AddItemToArray(variables_array, var_obj);
    }

    // Add variables array to body
    cJSON_AddItemToObject(body, "variables", variables_array);

    // Set response and cleanup
    set_response_success(response, body);
    cleanup_command_context(server);
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

int handle_terminate(DAPServer *server, cJSON *args, DAPResponse *response)
{
    (void)args; // Unused parameter

    if (!server || !response)
    {
        set_response_error(response, "Invalid server or response");
        return -1;
    }

    DAP_SERVER_DEBUG_LOG("Terminating debuggee");

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // If a terminate callback is registered, call it
    int result = dap_server_execute_callback(server,DAP_CMD_TERMINATE);
            
    if (result != 0)
    {
        cJSON_Delete(body);
        set_response_error(response, "Terminate command callback failed");
        return -1;
    }


    // Send terminated event
    cJSON *event_body = cJSON_CreateObject();
    if (event_body)
    {
        // The terminated event can optionally include a 'restart' attribute
        dap_server_send_event(server, "terminated", event_body);
    }

    set_response_success(response, body);
    return 0;
}

int handle_restart(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server || !response)
    {
        set_response_error(response, "Invalid server or response");
        return -1;
    }

    // Initialize the command context for restart
    server->current_command.type = DAP_CMD_RESTART;
    memset(&server->current_command.context.restart, 0, sizeof(RestartCommandContext));

    // Parse arguments if present
    if (args)
    {
        // Check if noDebug option is set
        cJSON *no_debug_json = cJSON_GetObjectItem(args, "noDebug");
        if (no_debug_json && cJSON_IsBool(no_debug_json) && cJSON_IsTrue(no_debug_json))
        {
            server->current_command.context.restart.no_debug = true;
            DAP_SERVER_DEBUG_LOG("Restart with noDebug option");
        }

        // Parse the arguments field which can contain launch or attach arguments
        cJSON *arguments_json = cJSON_GetObjectItem(args, "arguments");
        if (arguments_json && cJSON_IsObject(arguments_json))
        {
            // Store the arguments in the restart context
            server->current_command.context.restart.restart_args = cJSON_Duplicate(arguments_json, 1);
            if (!server->current_command.context.restart.restart_args)
            {
                DAP_SERVER_DEBUG_LOG("Failed to duplicate restart arguments");
            }
        }
    }

    // Call the implementation callback if registered
    bool callback_success = true;
    
    
    
    int callback_result =  dap_server_execute_callback(server, DAP_CMD_RESTART);
    
    if (callback_result != 0)
    {
        callback_success = false;
        DAP_SERVER_DEBUG_LOG("Restart implementation callback failed with code %d", callback_result);
    }
    

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Set response according to callback result
    if (callback_success)
    {
        set_response_success(response, body);
        DAP_SERVER_DEBUG_LOG("Restart command succeeded");
    }
    else
    {
        cJSON_Delete(body); // Must delete body as we're not passing it to set_response_error
        set_response_error(response, "Restart command failed");
    }

    // Note: Context resources will be cleaned up by cleanup_command_context

    return 0;
}

// Define a struct for exception breakpoint data
typedef struct {
    const char **filter_ids;
    const char **filter_conditions;
    int filter_count;
    int condition_count;
} ExceptionBreakpointData;

// Helper function to clean up exception breakpoint data
static void cleanup_exception_breakpoint_data(ExceptionBreakpointData *data) {
    if (!data) return;
    
    if (data->filter_ids) {
        for (int i = 0; i < data->filter_count; i++) {
            if (data->filter_ids[i]) {
                free((void *)data->filter_ids[i]);
                data->filter_ids[i] = NULL;
            }
        }
        free(data->filter_ids);
        data->filter_ids = NULL;
    }
    
    if (data->filter_conditions) {
        for (int i = 0; i < data->condition_count; i++) {
            if (data->filter_conditions[i]) {
                free((void *)data->filter_conditions[i]);
                data->filter_conditions[i] = NULL;
            }
        }
        free(data->filter_conditions);
        data->filter_conditions = NULL;
    }
    
    data->filter_count = 0;
    data->condition_count = 0;
}

int handle_set_exception_breakpoints(DAPServer *server, cJSON *args, DAPResponse *response)
{
    if (!server || !args || !response)
    {
        set_response_error(response, "Invalid arguments");
        return -1;
    }

    DAP_SERVER_DEBUG_LOG("Handling setExceptionBreakpoints request");

    // Initialize command context
    server->current_command.type = DAP_CMD_SET_EXCEPTION_BREAKPOINTS;
    memset(&server->current_command.context.exception, 0, sizeof(ExceptionBreakpointCommandContext));

    // Initialize our data structure
    ExceptionBreakpointData data = {0};
    
    // Parse filters array
    cJSON *filters = cJSON_GetObjectItem(args, "filters");
    if (!filters || !cJSON_IsArray(filters)) {
        // Return success with empty breakpoints array
        cJSON *body = cJSON_CreateObject();
        if (!body) {
            set_response_error(response, "Failed to create response body");
            return -1;
        }

        cJSON *breakpoints = cJSON_CreateArray();
        if (!breakpoints) {
            cJSON_Delete(body);
            set_response_error(response, "Failed to create breakpoints array");
            return -1;
        }

        cJSON_AddItemToObject(body, "breakpoints", breakpoints);
        set_response_success(response, body);
        return 0;
    }

    // Get filter count and allocate arrays
    data.filter_count = cJSON_GetArraySize(filters);
    data.filter_ids = calloc(data.filter_count, sizeof(char *));
    if (!data.filter_ids) {
        set_response_error(response, "Failed to allocate memory for filter IDs");
        return -1;
    }

    // Parse filter IDs
    for (int i = 0; i < data.filter_count; i++) {
        cJSON *filter = cJSON_GetArrayItem(filters, i);
        if (filter && cJSON_IsString(filter)) {
            data.filter_ids[i] = strdup(filter->valuestring);
            if (!data.filter_ids[i]) {
                cleanup_exception_breakpoint_data(&data);
                set_response_error(response, "Failed to allocate memory for filter ID");
                return -1;
            }
        }
    }

    // Parse filter options if present
    cJSON *filter_options = cJSON_GetObjectItem(args, "filterOptions");
    if (filter_options && cJSON_IsArray(filter_options)) {
        data.filter_conditions = calloc(data.filter_count, sizeof(char *));
        if (!data.filter_conditions) {
            cleanup_exception_breakpoint_data(&data);
            set_response_error(response, "Failed to allocate memory for filter conditions");
            return -1;
        }

        for (int i = 0; i < data.filter_count; i++) {
            cJSON *option = cJSON_GetArrayItem(filter_options, i);
            if (option) {
                cJSON *condition = cJSON_GetObjectItem(option, "condition");
                if (condition && cJSON_IsString(condition)) {
                    data.filter_conditions[i] = strdup(condition->valuestring);
                    if (!data.filter_conditions[i]) {
                        cleanup_exception_breakpoint_data(&data);
                        set_response_error(response, "Failed to allocate memory for filter condition");
                        return -1;
                    }
                }
            }
        }
        data.condition_count = data.filter_count;
    }

    // Store data in command context for callback
    server->current_command.context.exception.filters = data.filter_ids;
    server->current_command.context.exception.filter_count = data.filter_count;
    server->current_command.context.exception.conditions = data.filter_conditions;
    server->current_command.context.exception.condition_count = data.condition_count;

    // Execute callback
    int callback_result = dap_server_execute_callback(server, DAP_CMD_SET_EXCEPTION_BREAKPOINTS);

               
    if (callback_result != 0)
    {    
        set_response_error(response, "Breakpoint command callback failed");
        return -1;
    }

    
    // Create response
    cJSON *body = cJSON_CreateObject();
    if (!body) {
        cleanup_exception_breakpoint_data(&data);
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    cJSON *breakpoints = cJSON_CreateArray();
    if (!breakpoints) {
        cJSON_Delete(body);
        cleanup_exception_breakpoint_data(&data);
        set_response_error(response, "Failed to create breakpoints array");
        return -1;
    }

    // Add breakpoints to response
    for (int i = 0; i < data.filter_count; i++) {
        cJSON *breakpoint = cJSON_CreateObject();
        if (!breakpoint) {
            cJSON_Delete(body);
            cJSON_Delete(breakpoints);
            cleanup_exception_breakpoint_data(&data);
            set_response_error(response, "Failed to create breakpoint object");
            return -1;
        }

        cJSON_AddBoolToObject(breakpoint, "verified", true);
        cJSON_AddNumberToObject(breakpoint, "id", i);
        cJSON_AddItemToArray(breakpoints, breakpoint);
    }

    cJSON_AddItemToObject(body, "breakpoints", breakpoints);
    set_response_success(response, body);

    // Clean up our data structure
    //cleanup_exception_breakpoint_data(&data);

    return 0;
}

/**
 * @brief Helper function to free filter arrays and their contents
 *
 * @param filter_ids Array of filter ID strings
 * @param filter_conditions Array of filter condition strings
 * @param count Number of filters
 */
void free_filter_arrays(const char **filter_ids, const char **filter_conditions, int count)
{
    // First check if we have valid input
    if (!filter_ids || count <= 0)
    {
        return;
    }

    // Free each filter ID and condition string
    for (int i = 0; i < count; i++)
    {
        // Check if the current element exists before freeing
        if (filter_ids[i])
        {
            char *ptr = (char *)filter_ids[i];
            filter_ids[i] = NULL;  // Clear the pointer before freeing
            free(ptr);
        }

        // Check if filter_conditions exists and the current element exists before freeing
        if (filter_conditions && filter_conditions[i])
        {
            char *ptr = (char *)filter_conditions[i];
            filter_conditions[i] = NULL;  // Clear the pointer before freeing
            free(ptr);
        }
    }

    // Free the arrays themselves
    free((void *)filter_ids);
    if (filter_conditions)
    {
        free((void *)filter_conditions);
    }
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
    if (!server || !args || !response)
    {
        return -1;
    }

    // Parse required arguments
    cJSON *variablesReference = cJSON_GetObjectItem(args, "variablesReference");
    cJSON *name = cJSON_GetObjectItem(args, "name");
    cJSON *value = cJSON_GetObjectItem(args, "value");

    // Validate required arguments
    if (!variablesReference || !name || !value)
    {
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
    if (format)
    {
        server->current_command.context.set_variable.format = strdup(format->valuestring);
    }

    // Call the implementation callback 
    int result =  dap_server_execute_callback(server, DAP_CMD_SET_VARIABLE);        
    if (result != 0)
    {    
        // Callback failed - set error response
        set_response_error(response, "Callback failed for setVariable");
        return -1;
    }

    // Create response body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        cleanup_command_context(server);
        set_response_error(response, "Failed to create response body");
        return -1;
    }

    // Add required fields
    cJSON_AddStringToObject(body, "value", value->valuestring);

    // Add optional fields if available
    if (format)
    {
        cJSON_AddStringToObject(body, "type", "string"); // Example type
        cJSON_AddNumberToObject(body, "variablesReference", 0);
        cJSON_AddNumberToObject(body, "namedVariables", 0);
        cJSON_AddNumberToObject(body, "indexedVariables", 0);
        cJSON_AddStringToObject(body, "memoryReference", "");
    }

    set_response_success(response, body);    
    return 0;
}

/**
 * @brief Mock debugger implementation of the stackTrace command
 *
 * This callback provides stack frame information for the mock debugger.
 * It reads the command context from the server and updates the debugger state
 * with source information that will be used to build the stack frame response.
 *
 * @param server The DAP server instance containing the command context
 * @return int 0 on success, non-zero on failure
 */
int mock_handle_stack_trace(DAPServer *server)
{
    if (!server)
    {
        return -1;
    }

    // Log stack trace request to debugger console
    char log_message[256];
    snprintf(log_message, sizeof(log_message),
             "StackTrace request for thread %d (start=%d, count=%d)",
             server->debugger_state.current_thread_id,
             server->current_command.context.stack_trace.start_frame,
             server->current_command.context.stack_trace.levels);
    dap_server_send_output(server, log_message);

    // For the mock implementation, we'll use a default source file if none is set
    if (!server->debugger_state.source_path && !server->debugger_state.source_name)
    {
        // Example source information for the mock debugger
        if (!server->debugger_state.source_path)
        {
            server->debugger_state.source_path = strdup("/home/ronny/repos/ndasm/asm/intr.s");
        }

        if (!server->debugger_state.source_name)
        {
            server->debugger_state.source_name = strdup("intr.s");
        }

        snprintf(log_message, sizeof(log_message), "Using source: %s", server->debugger_state.source_path);
        dap_server_send_output(server, log_message);
    }

    // Set default line/column if not set
    if (server->debugger_state.source_line <= 0)
    {
        server->debugger_state.source_line = 1;
    }

    if (server->debugger_state.source_column <= 0)
    {
        server->debugger_state.source_column = 1;
    }

    // The handle_stack_trace function will build a response based on the debugger state

    return 0;
}

#if 0 // not used now
/**
 * @brief Create a presentationHint object for a variable
 *
 * This function creates a properly formatted presentationHint object as specified in the DAP spec.
 * The attributes array can contain any of the following values:
 * - "static" - Variable is static
 * - "constant" - Variable is a constant
 * - "readOnly" - Variable is read-only
 * - "rawString" - String should not be escaped/processed
 * - "hasObjectId" - Has an associated objectId (inspector/REPL)
 * - "canHaveObjectId" - Might have an objectId
 * - "hasSideEffects" - Evaluating causes side effects
 * - "hasDataBreakpoint" - Value is eligible for data breakpoint
 * - "hasChildren" - Variable has children
 *
 * @param kind The kind of variable (property, method, class, etc.)
 * @param attributes Array of string attributes (can be NULL)
 * @param num_attributes Number of attributes in the array
 * @param visibility Visibility string (public, private, protected, etc.)
 * @return cJSON* The created presentationHint object, or NULL on failure
 */
static cJSON *create_presentation_hint(const char *kind, const char **attributes, int num_attributes, const char *visibility)
{
    cJSON *hint = cJSON_CreateObject();
    if (!hint)
    {
        return NULL;
    }

    // Add kind if provided
    if (kind)
    {
        cJSON_AddStringToObject(hint, "kind", kind);
    }

    // Add attributes array if provided
    if (attributes && num_attributes > 0)
    {
        cJSON *attrs_array = cJSON_CreateArray();
        if (attrs_array)
        {
            for (int i = 0; i < num_attributes; i++)
            {
                if (attributes[i])
                {
                    cJSON_AddItemToArray(attrs_array, cJSON_CreateString(attributes[i]));
                }
            }
            cJSON_AddItemToObject(hint, "attributes", attrs_array);
        }
    }

    // Add visibility if provided
    if (visibility)
    {
        cJSON_AddStringToObject(hint, "visibility", visibility);
    }

    return hint;
}
#endif
/**
 * @brief Helper function to clean up DAPVariable array
 * @param variables Array of variables to free
 * @param count Number of variables in the array
 */
void free_variable_array(DAPVariable *variables, int count)
{
    if (!variables || count <= 0)
    {
        return;
    }

    for (int i = 0; i < count; i++)
    {
        // Free all dynamically allocated fields in each variable
        if (variables[i].name)
        {
            free(variables[i].name);
        }
        if (variables[i].value)
        {
            free(variables[i].value);
        }
        if (variables[i].type)
        {
            free(variables[i].type);
        }
        if (variables[i].evaluate_name)
        {
            free(variables[i].evaluate_name);
        }
    }

    // Free the array itself
    free(variables);
}
