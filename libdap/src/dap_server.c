/**
 * @file dap_server.c
 * @brief Server implementation for the DAP library
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>


#include "dap_server.h"
#include "dap_error.h"
#include "dap_types.h"
#include "dap_transport.h"
#include "dap_protocol.h"
#include <cjson/cJSON.h>
#include "dap_server_cmds.h"

#include "dap_types.h"
#include <cjson/cJSON.h>


DAPServer *dap_server_create(const DAPServerConfig *config)
{
    if (!config)
    {
        return NULL;
    }

    DAPServer *server = calloc(1, sizeof(DAPServer));
    if (!server)
    {
        return NULL;
    }

    if (dap_server_init(server, config) < 0)
    {
        free(server);
        return NULL;
    }

    return server;
}

int dap_server_init(DAPServer *server, const DAPServerConfig *config)
{
    if (!server || !config)
    {
        return -1;
    }

    server->transport = dap_transport_create(&config->transport);
    if (!server->transport)
    {
        return -1;
    }

    memcpy(&server->config, config, sizeof(DAPServerConfig));
    server->is_initialized = true;
    server->is_running = false;
    server->sequence = 0;
    server->current_thread_id = 0;

    // Initialize command handlers on server init
    initialize_command_handlers(server);

    return 0;
}

/**
 * @brief Start the DAP server
 *
 * @param server Server instance
 * @return int 0 on success, -1 on error
 */
int dap_server_start(DAPServer *server)
{
    if (!server)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid server");
        return -1;
    }

    if (dap_transport_start(server->transport) < 0)
    {
        dap_error_set(DAP_ERROR_TRANSPORT, "Failed to start transport");
        return -1;
    }

    server->is_running = true;
    return 0;
}

/**
 * @brief Stop the DAP server
 *
 * @param server Server instance
 * @return int 0 on success, -1 on error
 */
int dap_server_stop(DAPServer *server)
{
    if (!server)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid server");
        return -1;
    }

    if (dap_transport_stop(server->transport) < 0)
    {
        dap_error_set(DAP_ERROR_TRANSPORT, "Failed to stop transport");
        return -1;
    }

    server->is_running = false;
    return 0;
}

/**
 * @brief Free the DAP server
 *
 * @param server Server instance
 */
void dap_server_free(DAPServer *server)
{
    if (!server)
        return;

    if (server->transport)
    {
        dap_transport_free(server->transport);
    }

    if (server->program_path)
    {
        free(server->program_path);
    }

    free(server);
}

/**
 * @brief Process a DAP message
 *
 * @param server Server instance
 * @param message Message to process
 * @return int 0 on success, -1 on error
 */
int dap_server_process_message(DAPServer *server, const char *message)
{
    if (!server || !message)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    // Parse message
    DAPMessageType type;
    DAPCommandType command;
    int sequence;
    cJSON *content = NULL;

    if (dap_parse_message(message, &type, &command, &sequence, &content) < 0)
    {
        return -1;
    }

    switch (type)
    {
    case DAP_MESSAGE_REQUEST:
        // Handle request
        if (dap_server_handle_request(server, command, sequence, content) < 0)
        {
            cJSON_Delete(content);
            return -1;
        }
        break;

    case DAP_MESSAGE_RESPONSE:
        // Handle response
        DAP_SERVER_DEBUG_LOG("Received response: sequence=%d", sequence);
        break;

    case DAP_MESSAGE_EVENT:
        // Handle event
        DAP_SERVER_DEBUG_LOG("Received event: type=%d. UNEXPECTED!", command);
        break;

    default:
        DAP_SERVER_DEBUG_LOG("Unknown message type: %d", type);
        cJSON_Delete(content);
        return -1;
    }

    cJSON_Delete(content);
    return 0;
}

/**
 * @brief Send a DAP response
 *
 * @param server Server instance
 * @param command Command type
 * @param sequence Sequence number
 * @param success Whether the request was successful
 * @param body Response body (JSON string)
 * @return int 0 on success, -1 on error
 */
int dap_server_send_response(DAPServer *server, DAPCommandType command,
                             int sequence, bool success, cJSON *body)
{
    if (!server)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid server");
        return -1;
    }

    cJSON *response = dap_create_response(command, sequence, success, body);
    if (!response)
    {
        return -1;
    }

    char *response_str = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    if (!response_str)
    {
        return -1;
    }

    if (dap_transport_send(server->transport, response_str) < 0)
    {
        dap_error_set(DAP_ERROR_TRANSPORT, "Failed to send response");
        free(response_str);
        return -1;
    }

    free(response_str);
    return 0;
}

/**
 * @brief Send an event to the client
 *
 * @param server Server instance
 * @param event_type Event type
 * @param body Event body (JSON string)
 * @return int 0 on success, -1 on error
 */
int dap_server_send_event(DAPServer *server, DAPEventType event_type, cJSON *body)
{
    if (!server)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid server");
        return -1;
    }

    cJSON *event = dap_create_event(event_type, body);
    if (!event)
    {
        return -1;
    }

    char *event_str = cJSON_PrintUnformatted(event);
    cJSON_Delete(event);

    if (!event_str)
    {
        return -1;
    }

    if (dap_transport_send(server->transport, event_str) < 0)
    {
        dap_error_set(DAP_ERROR_TRANSPORT, "Failed to send event");
        free(event_str);
        return -1;
    }

    free(event_str);
    return 0;
}

int dap_server_handle_request(DAPServer *server, DAPCommandType command,
                              int sequence, cJSON *content)
{
    if (!server)
    {
        DAP_SERVER_DEBUG_LOG("Invalid server pointer");
        dap_error_set(DAP_ERROR_INVALID_STATE, "Server not properly initialized");
        return -1;
    }

    DAP_SERVER_DEBUG_LOG("Handling request: command=%d, sequence=%d", command, sequence);
    if (content)
    {
        char *content_str = cJSON_PrintUnformatted(content);
        DAP_SERVER_DEBUG_LOG("Request content: %s", content_str);
        free(content_str);
    }

    // Create response structure
    DAPResponse response = {0};

    // Convert content to string for callback
    char *content_str = content ? cJSON_PrintUnformatted(content) : NULL;

    // Call the handler
    int result = dap_server_handle_command(server, command, content_str, &response);

    if (content_str)
    {
        free(content_str);
    }

    if (result < 0)
    {
        dap_error_set(DAP_ERROR_REQUEST_FAILED, "Command handler failed");
        if (response.error_message)
        {
            free(response.error_message);
        }
        if (response.data)
        {
            free(response.data);
        }
        return -1;
    }

    // Send the response with the same command type as the request
    cJSON *response_body = response.data ? cJSON_Parse(response.data) : cJSON_CreateObject();
    result = dap_server_send_response(server, command, sequence,
                                      response.success,
                                      response_body);

    // Clean up response
    if (response.error_message)
    {
        free(response.error_message);
    }
    if (response.data)
    {
        free(response.data);
    }

    return result;
}

int dap_server_run(DAPServer *server)
{
    if (!server)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid server");
        return -1;
    }

    if (!server->is_initialized)
    {
        dap_error_set(DAP_ERROR_INVALID_STATE, "Server not initialized");
        return -1;
    }

    while (server->is_running)
    {
        if (dap_transport_accept(server->transport) < 0)
        {
            continue;
        }

        while (server->is_running)
        {
            char *message = NULL;
            int result = dap_transport_receive(server->transport, &message);
            if (result < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    continue;
                }
                break;
            }

            if (!message)
            {
                break;
            }

            if (dap_server_process_message(server, message) < 0)
            {
                free(message);
                continue;
            }

            free(message);
        }
    }

    return 0;
}

// Update add_breakpoint to use MockDebugger
void add_breakpoint(DAPServer *server, const char *file_path, int line)
{
    // Check if breakpoint already exists
    for (int i = 0; i < server->breakpoint_count; i++)
    {
        if (server->breakpoints[i].source &&
            strcmp(server->breakpoints[i].source->path, file_path) == 0 &&
            server->breakpoints[i].line == line)
        {
            return; // Breakpoint already exists
        }
    }

    // Resize array if needed
    if (server->breakpoint_count >= MAX_BREAKPOINTS)
    {
        return;
    }

    DAPBreakpoint *new_breakpoints = realloc(server->breakpoints,
                                             (server->breakpoint_count + 1) * sizeof(DAPBreakpoint));
    if (!new_breakpoints)
    {
        return;
    }

    server->breakpoints = new_breakpoints;
    server->breakpoints[server->breakpoint_count].line = line;
    server->breakpoints[server->breakpoint_count].column = 0;
    server->breakpoints[server->breakpoint_count].verified = true;

    // Set the source
    DAPSource *bp_source = malloc(sizeof(DAPSource));
    if (bp_source)
    {
        bp_source->path = strdup(file_path);
        server->breakpoints[server->breakpoint_count].source = bp_source;
    }

    server->breakpoint_count++;
}

// Update remove_breakpoints to use MockDebugger
void remove_breakpoints(DAPServer *server, const char *file_path)
{
    for (int i = 0; i < server->breakpoint_count; i++)
    {
        if (server->breakpoints[i].source &&
            strcmp(server->breakpoints[i].source->path, file_path) == 0)
        {
            // Free the source
            if (server->breakpoints[i].source)
            {
                free(server->breakpoints[i].source->path);
                free(server->breakpoints[i].source);
            }

            // Move last breakpoint to this position
            if (i < server->breakpoint_count - 1)
            {
                server->breakpoints[i] = server->breakpoints[server->breakpoint_count - 1];
            }
            server->breakpoint_count--;
            i--; // Check this position again
        }
    }
}

// Update get_breakpoints_for_file to use MockDebugger
cJSON *get_breakpoints_for_file(DAPServer *server, const char *file_path)
{
    cJSON *breakpoints = cJSON_CreateArray();
    if (!breakpoints)
        return NULL;

    for (int i = 0; i < server->breakpoint_count; i++)
    {
        if (server->breakpoints[i].source &&
            strcmp(server->breakpoints[i].source->path, file_path) == 0)
        {
            cJSON *bp = cJSON_CreateObject();
            if (bp)
            {
                cJSON_AddNumberToObject(bp, "line", server->breakpoints[i].line);
                cJSON_AddBoolToObject(bp, "verified", server->breakpoints[i].verified);
                cJSON_AddItemToArray(breakpoints, bp);
            }
        }
    }

    return breakpoints;
}

// Add helper function for line mapping
int get_line_for_address(DAPServer *server, uint32_t address)
{
    for (int i = 0; i < server->line_map_count; i++)
    {
        if (server->line_maps[i].address == address)
        {
            return server->line_maps[i].line;
        }
    }
    return -1;
}

// Fix pointer type in add_line_map
void add_line_map(DAPServer *server, const char *file_path, int line, uint32_t address)
{
    if (server->line_map_count >= server->line_map_capacity)
    {
        size_t new_capacity = server->line_map_capacity == 0 ? 16 : server->line_map_capacity * 2;
        SourceLineMap *new_maps = realloc(server->line_maps, new_capacity * sizeof(SourceLineMap));
        if (!new_maps)
        {
            return;
        }
        server->line_maps = new_maps;
        server->line_map_capacity = new_capacity;
    }

    server->line_maps[server->line_map_count].file_path = strdup(file_path);
    server->line_maps[server->line_map_count].line = line;
    server->line_maps[server->line_map_count].address = address;
    server->line_map_count++;
}

// Special handler for launch command to preserve the existing behavior
static int handle_launch_wrapper(DAPServer *server, cJSON *json_args, DAPResponse *response) {
    DAP_SERVER_DEBUG_LOG("About to handle launch request");
    int result = handle_launch(server, json_args, response);
    DAP_SERVER_DEBUG_LOG("Launch request handled, result=%d", result);

    // Always return 0 for launch even if there was an error
    // This ensures that the response is sent back to the client
    if (result != 0) {
        DAP_SERVER_DEBUG_LOG("Converting error result %d to success 0 to ensure response is sent", result);
        result = 0;
    }

    // Store a copy of the args for later sending the event
    cJSON *program = json_args ? cJSON_GetObjectItem(json_args, "program") : NULL;
    cJSON *args_array = json_args ? cJSON_GetObjectItem(json_args, "args") : NULL;

    // Schedule the event to be sent after response
    if (response->success && program && cJSON_IsString(program)) {
        // Small delay to ensure response is processed first
        usleep(10000); // 10ms delay
        
        
        DAP_SERVER_DEBUG_LOG("Sending stopped event after launch response");
    
        
        cJSON* event_body = cJSON_CreateObject();
        if (!event_body) {
            return -1;
        }
    
        cJSON_AddStringToObject(event_body, "reason", "entry");
        cJSON_AddNumberToObject(event_body, "threadId", 1);
        cJSON_AddBoolToObject(event_body, "allThreadsStopped", true);
    
        // Add program info to event
        cJSON_AddStringToObject(event_body, "program", program->valuestring);
        if (args_array) {
            cJSON_AddItemToObject(event_body, "args", cJSON_Duplicate(args_array, 1));
        }

        dap_server_send_event(server, DAP_EVENT_STOPPED, event_body);
        cJSON_Delete(event_body);
    }

    return result;
}
// Initialize the command handlers array in the server struct
void initialize_command_handlers(DAPServer *server) {
    // Clear the array first
    memset(server->command_handlers, 0, sizeof(server->command_handlers));

    // Set up the handlers for each command type - explicitly listing all handlers
    // for better documentation and maintainability
    server->command_handlers[DAP_CMD_INITIALIZE] = handle_initialize;
    server->command_handlers[DAP_CMD_LAUNCH] = handle_launch_wrapper;
    server->command_handlers[DAP_CMD_ATTACH] = handle_attach;
    server->command_handlers[DAP_CMD_DISCONNECT] = handle_disconnect;
    server->command_handlers[DAP_CMD_TERMINATE] = handle_terminate;
    server->command_handlers[DAP_CMD_RESTART] = handle_restart;
    server->command_handlers[DAP_CMD_SET_BREAKPOINTS] = handle_set_breakpoints;
    server->command_handlers[DAP_CMD_CLEAR_BREAKPOINTS] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_SET_FUNCTION_BREAKPOINTS] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_SET_EXCEPTION_BREAKPOINTS] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_CONTINUE] = handle_continue;
    server->command_handlers[DAP_CMD_NEXT] = handle_next;
    server->command_handlers[DAP_CMD_STEP_IN] = handle_step_in;
    server->command_handlers[DAP_CMD_STEP_OUT] = handle_step_out;
    server->command_handlers[DAP_CMD_PAUSE] = handle_pause;
    server->command_handlers[DAP_CMD_STACK_TRACE] = handle_stack_trace;
    server->command_handlers[DAP_CMD_SCOPES] = handle_scopes;
    server->command_handlers[DAP_CMD_VARIABLES] = handle_variables;
    server->command_handlers[DAP_CMD_SET_VARIABLE] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_SOURCE] = handle_source;
    server->command_handlers[DAP_CMD_THREADS] = handle_threads;
    server->command_handlers[DAP_CMD_EVALUATE] = handle_evaluate;
    server->command_handlers[DAP_CMD_SET_EXPRESSION] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_LOADED_SOURCES] = handle_loaded_sources;
    server->command_handlers[DAP_CMD_READ_MEMORY] = handle_read_memory;
    server->command_handlers[DAP_CMD_WRITE_MEMORY] = handle_write_memory;
    server->command_handlers[DAP_CMD_DISASSEMBLE] = handle_disassemble;
    server->command_handlers[DAP_CMD_READ_REGISTERS] = handle_read_registers;
    server->command_handlers[DAP_CMD_WRITE_REGISTERS] = handle_write_register;
    server->command_handlers[DAP_CMD_CANCEL] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_CONFIGURATION_DONE] = handle_configuration_done;
    server->command_handlers[DAP_CMD_TERMINATE_THREADS] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_COMPLETIONS] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_EXCEPTION_INFO] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_DATA_BREAKPOINT_INFO] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_SET_DATA_BREAKPOINTS] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_SET_INSTRUCTION_BREAKPOINTS] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_MODULES] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_STEP_BACK] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_REVERSE_CONTINUE] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_RESTART_FRAME] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_GOTO] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_SET_EXCEPTION_FILTERS] = NULL;  // Not implemented
}

int dap_server_handle_command(DAPServer *server, DAPCommandType command,
                              const char *args, DAPResponse *response)
{
    if (!response || !server)
    {
        return -1;
    }

    DAP_SERVER_DEBUG_LOG("Handling command: %d", (int)command);

    // Convert args string to cJSON if needed
    cJSON *json_args = args ? cJSON_Parse(args) : NULL;
    if (args && !json_args)
    {
        response->success = false;
        response->error_message = strdup("Failed to parse arguments");
        return 0; // Return 0 even for errors to ensure response is sent
    }

    // Validate command index
    if (command < 0 || command >= MAX_DAP_COMMANDS) {
        response->success = false;
        response->error_message = strdup("Unknown command");
        if (json_args) {
            cJSON_Delete(json_args);
        }
        return 0;
    }

    // Get handler from server's command handlers array
    DAPCommandHandler handler = server->command_handlers[command];
    
    // Execute handler if available
    int result = 0;
    if (handler) {
        result = handler(server, json_args, response);
    } else {
        // No handler for this command
        response->success = false;
        response->error_message = strdup("Command not implemented");
    }

    if (json_args)
    {
        cJSON_Delete(json_args);
    }

    // Ensure we always return 0 so that responses are sent to the client
    // DAP protocol requires all requests to have responses, even errors
    if (result != 0)
    {
        DAP_SERVER_DEBUG_LOG("Command handler returned error %d, converting to 0 to ensure response is sent", result);
        result = 0;
    }

    return result;
}

/* Breakpoint and line map cleanup */

void cleanup_breakpoints(DAPServer *dap_server)
{
    if (dap_server->breakpoints)
    {
        for (int i = 0; i < dap_server->breakpoint_count; i++)
        {
            if (dap_server->breakpoints[i].source)
            {
                free(dap_server->breakpoints[i].source->path);
                free(dap_server->breakpoints[i].source);
            }
        }
        free(dap_server->breakpoints);
        dap_server->breakpoints = NULL;
        dap_server->breakpoint_count = 0;
    }
}

void cleanup_line_maps(DAPServer *dap_server)
{
    if (dap_server->line_maps)
    {
        for (int i = 0; i < dap_server->line_map_count; i++)
        {
            free((void *)dap_server->line_maps[i].file_path);
        }
        free(dap_server->line_maps);
        dap_server->line_maps = NULL;
        dap_server->line_map_count = 0;
        dap_server->line_map_capacity = 0;
    }
}
