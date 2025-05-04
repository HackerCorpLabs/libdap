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
    
    // Enable debug logging for the transport
    server->transport->debuglog = true;

    memcpy(&server->config, config, sizeof(DAPServerConfig));
    server->is_initialized = false; // Will be set to true after receiving initialize request
    server->is_running = false;
    server->attached = false;
    server->paused = false;
    server->sequence = 0;
    server->current_thread_id = 0;
    server->current_line = 0;
    server->current_column = 0;
    server->current_pc = 0;
    
    // Initialize the stepping function pointers
    server->step_cpu = NULL;
    server->step_cpu_line = NULL; 
    server->step_cpu_statement = NULL;

    // Initialize client capabilities with default values
    server->client_capabilities.clientID = NULL;
    server->client_capabilities.clientName = NULL;
    server->client_capabilities.adapterID = NULL;
    server->client_capabilities.locale = NULL;
    server->client_capabilities.pathFormat = NULL;
    server->client_capabilities.linesStartAt1 = true; // Default to 1-based line numbers
    server->client_capabilities.columnsStartAt1 = true; // Default to 1-based column numbers
    server->client_capabilities.supportsVariableType = false;
    server->client_capabilities.supportsVariablePaging = false;
    server->client_capabilities.supportsRunInTerminalRequest = false;
    server->client_capabilities.supportsMemoryReferences = false;
    server->client_capabilities.supportsProgressReporting = false;
    server->client_capabilities.supportsInvalidatedEvent = false;
    server->client_capabilities.supportsMemoryEvent = false;
    server->client_capabilities.supportsArgsCanBeInterpretedByShell = false;
    server->client_capabilities.supportsStartDebuggingRequest = false;
    server->client_capabilities.supportsANSIStyling = false;

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
 * @brief Clean up resources used by a DAP server
 * @param server Server instance
 */
void dap_server_cleanup(DAPServer *server)
{
    if (!server)
        return;

    // Free client capabilities strings
    if (server->client_capabilities.clientID) {
        free(server->client_capabilities.clientID);
        server->client_capabilities.clientID = NULL;
    }
    
    if (server->client_capabilities.clientName) {
        free(server->client_capabilities.clientName);
        server->client_capabilities.clientName = NULL;
    }
    
    if (server->client_capabilities.adapterID) {
        free(server->client_capabilities.adapterID);
        server->client_capabilities.adapterID = NULL;
    }
    
    if (server->client_capabilities.locale) {
        free(server->client_capabilities.locale);
        server->client_capabilities.locale = NULL;
    }
    
    if (server->client_capabilities.pathFormat) {
        free(server->client_capabilities.pathFormat);
        server->client_capabilities.pathFormat = NULL;
    }

    if (server->transport)
    {
        dap_transport_free(server->transport);
        server->transport = NULL;
    }

    if (server->program_path)
    {
        free(server->program_path);
        server->program_path = NULL;
    }

    // Clean up current source information
    if (server->current_source)
    {
        if (server->current_source->path)
        {
            free((void *)server->current_source->path);
        }
        if (server->current_source->name)
        {
            free((void *)server->current_source->name);
        }
        free((void *)server->current_source);
        server->current_source = NULL;
    }

    // Clean up breakpoints and line maps
    cleanup_breakpoints(server);
    cleanup_line_maps(server);
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

    // Clean up all resources
    dap_server_cleanup(server);
    
    // Free the server structure itself
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

    return dap_server_handle_request(server, message);
}

/**
 * @brief Handle a specific DAP command by calling the appropriate handler
 *
 * @param server Server instance
 * @param command Command type to handle
 * @param args_str Arguments for the command as JSON string, or NULL if json_args is provided
 * @param json_args Arguments for the command as cJSON object, or NULL if args_str is provided
 * @param response Response structure to fill
 * @return int 0 on success, non-zero on failure
 */
int dap_server_handle_command(DAPServer *server, DAPCommandType command,
                             const char *args_str, cJSON *json_args, DAPResponse *response)
{
    if (!response || !server)
    {
        return -1;
    }

    DAP_SERVER_DEBUG_LOG("Handling command: %d", (int)command);

    // Convert args string to cJSON if needed
    if (!json_args && args_str)
    {
        json_args = cJSON_Parse(args_str);
        
        if (!json_args)
        {
            response->success = false;
            response->error_message = strdup("Failed to parse arguments");
            return -1;
        }
    }

    // Log the JSON arguments if available
    if (json_args)
    {
        char* args_json_str = cJSON_Print(json_args);
        if (args_json_str)
        {
            DAP_SERVER_DEBUG_LOG("Command arguments: %s", args_json_str);
            free(args_json_str);
        }
    }

    // Initialize response
    response->success = false;
    response->error_message = NULL;
    response->data = NULL;

    // Get appropriate handler
    DAPCommandHandler handler = NULL;
    if (command >= 0 && command < DAP_CMD_MAX)
    {
        handler = server->command_handlers[command];
    }

    // Call handler if available
    int result = -1;
    if (handler)
    {
        result = handler(server, json_args, response);
    }
    else
    {
        response->success = false;
        response->error_message = strdup("Unsupported command");
        result = -1;
    }

    // Always free the JSON args, whether from args_str or passed in
    // This simplifies memory management by having this function take ownership
    if (json_args)
    {
        cJSON_Delete(json_args);
    }

    return result;
}

/**
 * @brief Handle an incoming DAP request string
 *
 * @param server Server instance
 * @param request JSON request string
 * @return int 0 on success, -1 on error
 */
int dap_server_handle_request(DAPServer *server, const char *request)
{
    if (!server || !request)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    // Parse message
    DAPMessageType type;
    DAPCommandType command;
    int sequence;
    cJSON *content = NULL;

    if (dap_parse_message(request, &type, &command, &sequence, &content) < 0)
    {
        return -1;
    }

    if (type != DAP_MESSAGE_REQUEST)
    {
        DAP_SERVER_DEBUG_LOG("Received message is not a request: type=%d", type);
        cJSON_Delete(content);
        return -1;
    }

    // Handle request
    DAPResponse response = {0};
    
    // Call the appropriate command handler - dap_server_handle_command takes ownership of content
    // It will free content when done, so we don't need to free it here
    int result = dap_server_handle_command(server, command, NULL, content, &response);
    
    // Send the response with the same command type as the request
    if (result >= 0)
    {
        cJSON *response_body = response.data ? cJSON_Parse(response.data) : cJSON_CreateObject();
        dap_server_send_response(server, command, sequence, response.success, response_body);
        //cJSON_Delete(response_body); (double free)
        
        // If this was an initialize request and it was successful, send the 'initialized' event
        if (command == DAP_CMD_INITIALIZE && response.success) {
            cJSON *event_body = cJSON_CreateObject();
            if (event_body) {
                dap_server_send_event(server, "initialized", event_body);
                cJSON_Delete(event_body);
            }
        }
    }

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

/**
 * @brief Send a response to a request based on DAPResponse struct
 *
 * @param server Server instance
 * @param response Response data structure
 * @return int 0 on success, -1 on error
 */
int dap_server_send_response_struct(DAPServer *server, const DAPResponse *response)
{
    if (!server || !response)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    // Create JSON object from response data if available
    cJSON *response_obj = NULL;
    if (response->data)
    {
        response_obj = cJSON_Parse(response->data);
        if (!response_obj)
        {
            dap_error_set(DAP_ERROR_PARSE_ERROR, "Failed to parse response data");
            return -1;
        }
    }
    else
    {
        response_obj = cJSON_CreateObject();
        if (!response_obj)
        {
            dap_error_set(DAP_ERROR_MEMORY, "Failed to create response object");
            return -1;
        }
    }

    // Create response JSON with status and body
    cJSON *full_response = cJSON_CreateObject();
    if (!full_response)
    {
        cJSON_Delete(response_obj);
        dap_error_set(DAP_ERROR_MEMORY, "Failed to create full response object");
        return -1;
    }

    // Add common fields
    cJSON_AddStringToObject(full_response, "type", "response");
    cJSON_AddBoolToObject(full_response, "success", response->success);
    
    // Add error message if failed
    if (!response->success && response->error_message)
    {
        cJSON *message = cJSON_CreateObject();
        cJSON_AddStringToObject(message, "message", response->error_message);
        cJSON_AddItemToObject(full_response, "message", message);
    }

    // Add body
    cJSON_AddItemToObject(full_response, "body", response_obj);

    // Convert to string and send
    char *response_str = cJSON_PrintUnformatted(full_response);
    cJSON_Delete(full_response);

    if (!response_str)
    {
        dap_error_set(DAP_ERROR_MEMORY, "Failed to convert response to string");
        return -1;
    }

    int result = dap_transport_send(server->transport, response_str);
    free(response_str);

    if (result < 0)
    {
        dap_error_set(DAP_ERROR_TRANSPORT, "Failed to send response");
        return -1;
    }

    return 0;
}

/**
 * @brief Send an event to the client with a string event type
 *
 * Creates a properly formatted DAP event and sends it to the client.
 * Events are asynchronous notifications that can be sent at any time
 * to inform the client about state changes or other information.
 * 
 * This function:
 * 1. Creates a new event JSON structure
 * 2. Sets the common fields (type="event", event=event_type)
 * 3. Assigns a sequence number from the server
 * 4. Duplicates and attaches the body (if provided)
 * 5. Serializes and sends via transport
 *
 * @param server Server instance
 * @param event_type Event type as string (e.g., "initialized", "stopped", "output")
 * @param body Event body (JSON object) containing event-specific data
 * @return 0 on success, non-zero on failure
 * 
 * @note This function DUPLICATES the provided body, so the caller
 *       maintains ownership and must free the original body if needed.
 */
int dap_server_send_event(DAPServer *server, const char *event_type, cJSON *body)
{
    if (!server || !event_type)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    // Create event object
    cJSON *event = cJSON_CreateObject();
    if (!event)
    {
        dap_error_set(DAP_ERROR_MEMORY, "Failed to create event object");
        return -1;
    }

    // Add common fields
    cJSON_AddStringToObject(event, "type", "event");
    cJSON_AddNumberToObject(event, "seq", server->sequence++);
    cJSON_AddStringToObject(event, "event", event_type);

    // Add body if provided
    if (body)
    {
        cJSON_AddItemToObject(event, "body", body);
    }
    else
    {
        cJSON_AddObjectToObject(event, "body");
    }

    // Convert to string and send
    char *event_str = cJSON_PrintUnformatted(event);
    cJSON_Delete(event);
    
    if (!event_str)
    {
        dap_error_set(DAP_ERROR_MEMORY, "Failed to convert event to string");
        return -1;
    }

    // Log the full event content
    DAP_SERVER_DEBUG_LOG("Sending event: %s", event_str);

    if (dap_transport_send(server->transport, event_str) < 0)
    {
        dap_error_set(DAP_ERROR_TRANSPORT, "Failed to send event");
        free(event_str);
        return -1;
    }

    free(event_str);
    return 0;
}

/**
 * @brief Send an event using enum type instead of string (deprecated)
 * 
 * Legacy implementation that uses enum values for event types instead of
 * the string-based approach defined in the DAP specification.
 * 
 * This function has the same basic functionality as dap_server_send_event()
 * but uses the older enum-based event type system. It's maintained for
 * backward compatibility with code that hasn't been updated to use
 * string-based event types.
 * 
 * @deprecated Use dap_server_send_event() instead which follows the DAP specification
 *             by using string-based event types. This function may be removed in future versions.
 * 
 * @note Like dap_server_send_event(), this function duplicates the body object,
 *       so the caller retains ownership of the original body.
 */
int dap_server_send_event_enum(DAPServer *server, DAPEventType event_type, cJSON *body)
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

/**
 * @brief Clean up breakpoints and associated resources
 * 
 * @param dap_server Server instance
 */
void cleanup_breakpoints(DAPServer *dap_server)
{
    if (!dap_server || !dap_server->breakpoints)
        return;

    for (int i = 0; i < dap_server->breakpoint_count; i++)
    {
        if (dap_server->breakpoints[i].source)
        {
            free((void *)dap_server->breakpoints[i].source->path);
            free((void *)dap_server->breakpoints[i].source->name);
            free(dap_server->breakpoints[i].source);
        }
        
        // Free any condition strings if they exist
        if (dap_server->breakpoints[i].condition)
            free((void *)dap_server->breakpoints[i].condition);
        
        if (dap_server->breakpoints[i].hit_condition)
            free((void *)dap_server->breakpoints[i].hit_condition);
        
        if (dap_server->breakpoints[i].log_message)
            free((void *)dap_server->breakpoints[i].log_message);
    }
    
    free(dap_server->breakpoints);
    dap_server->breakpoints = NULL;
    dap_server->breakpoint_count = 0;
}

/**
 * @brief Clean up line maps and associated resources
 * 
 * @param dap_server Server instance
 */
void cleanup_line_maps(DAPServer *dap_server)
{
    if (!dap_server || !dap_server->line_maps)
        return;

    for (int i = 0; i < dap_server->line_map_count; i++)
    {
        if (dap_server->line_maps[i].file_path)
            free((void *)dap_server->line_maps[i].file_path);
    }
    
    free(dap_server->line_maps);
    dap_server->line_maps = NULL;
    dap_server->line_map_count = 0;
    dap_server->line_map_capacity = 0;
}

/**
 * @brief Get source line for a memory address
 * 
 * @param server Server instance
 * @param address Memory address to look up
 * @return int Line number or -1 if not found
 */
int get_line_for_address(DAPServer *server, uint32_t address)
{
    if (!server || !server->line_maps)
    {
        return -1;
    }

    for (int i = 0; i < server->line_map_count; i++)
    {
        if (server->line_maps[i].address == address)
        {
            return server->line_maps[i].dap_line;
        }
    }
    return -1;
}

/**
 * @brief Add a source line mapping with address information
 * 
 * @param server Server instance
 * @param file_path Source file path
 * @param line Line number
 * @param address Memory address
 */
void add_line_map(DAPServer *server, const char *file_path, int line, uint32_t address)
{
    if (!server || !file_path)
    {
        return;
    }

    // Resize the line maps array if needed
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

    // Initialize the new line map
    server->line_maps[server->line_map_count].file_path = strdup(file_path);
    server->line_maps[server->line_map_count].original_line = line;
    server->line_maps[server->line_map_count].dap_line = line;  // Use the same line by default
    server->line_maps[server->line_map_count].address = address;
    server->line_map_count++;
}

/**
 * @brief Special handler for launch command to preserve the existing behavior
 * @param server Server instance
 * @param json_args JSON arguments
 * @param response Response structure to fill
 * @return 0 on success, non-zero on failure
 */
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

        dap_server_send_event(server, "stopped", event_body);
        cJSON_Delete(event_body);
    }

    return result;
}

/**
 * @brief Initialize the command handlers array in the server struct
 * @param server Server instance to initialize handlers for
 */
void initialize_command_handlers(DAPServer *server) {
    // Clear the array first
    memset(server->command_handlers, 0, sizeof(server->command_handlers));

    // Set up the handlers for each command type - explicitly listing all handlers
    // for better documentation and maintainability
    server->command_handlers[DAP_CMD_INITIALIZE] = &handle_initialize;
    server->command_handlers[DAP_CMD_LAUNCH] = &handle_launch_wrapper;
    server->command_handlers[DAP_CMD_ATTACH] = &handle_attach;
    server->command_handlers[DAP_CMD_DISCONNECT] = &handle_disconnect;
    server->command_handlers[DAP_CMD_TERMINATE] = &handle_terminate;
    server->command_handlers[DAP_CMD_RESTART] = &handle_restart;
    server->command_handlers[DAP_CMD_SET_BREAKPOINTS] = &handle_set_breakpoints;
    server->command_handlers[DAP_CMD_CLEAR_BREAKPOINTS] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_SET_FUNCTION_BREAKPOINTS] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_SET_EXCEPTION_BREAKPOINTS] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_CONTINUE] = &handle_continue;
    server->command_handlers[DAP_CMD_NEXT] = &handle_next;
    server->command_handlers[DAP_CMD_STEP_IN] = &handle_step_in;
    server->command_handlers[DAP_CMD_STEP_OUT] = &handle_step_out;
    server->command_handlers[DAP_CMD_PAUSE] = &handle_pause;
    server->command_handlers[DAP_CMD_STACK_TRACE] = &handle_stack_trace;
    server->command_handlers[DAP_CMD_SCOPES] = &handle_scopes;
    server->command_handlers[DAP_CMD_VARIABLES] = &handle_variables;
    server->command_handlers[DAP_CMD_SET_VARIABLE] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_SOURCE] = &handle_source;
    server->command_handlers[DAP_CMD_THREADS] = &handle_threads;
    server->command_handlers[DAP_CMD_EVALUATE] = &handle_evaluate;
    server->command_handlers[DAP_CMD_SET_EXPRESSION] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_LOADED_SOURCES] = &handle_loaded_sources;
    server->command_handlers[DAP_CMD_READ_MEMORY] = &handle_read_memory;
    server->command_handlers[DAP_CMD_WRITE_MEMORY] = &handle_write_memory;
    server->command_handlers[DAP_CMD_DISASSEMBLE] = &handle_disassemble;
    server->command_handlers[DAP_CMD_READ_REGISTERS] = &handle_read_registers;
    server->command_handlers[DAP_CMD_WRITE_REGISTERS] = &handle_write_register;
    server->command_handlers[DAP_CMD_CANCEL] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_CONFIGURATION_DONE] = &handle_configuration_done;
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

/**
 * @brief Send a DAP response to a client request
 * 
 * Creates a properly formatted response object and sends it to the client.
 * This function handles the complete lifecycle of creating and sending the response:
 * 1. Creates the response JSON structure with proper fields
 * 2. Attaches the body to the response
 * 3. Serializes to string and sends via transport
 * 4. Cleans up temporary objects
 *
 * @param server Server instance
 * @param command Command type (must match the originating request)
 * @param sequence Sequence number (must match the originating request)
 * @param success Whether the request was successfully processed
 * @param body Response body as a JSON object
 * @return int 0 on success, -1 on error
 * 
 * @note IMPORTANT: This function takes ownership of the body cJSON object and will free it.
 *       Do not access or free the body after calling this function.
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

    // Log the full response content
    DAP_SERVER_DEBUG_LOG("Sending response: %s", response_str);

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
 * @brief Run the DAP server main loop
 * 
 * @param server Server instance
 * @return int 0 on success, -1 on error
 */
int dap_server_run(DAPServer *server)
{
    if (!server)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid server");
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
