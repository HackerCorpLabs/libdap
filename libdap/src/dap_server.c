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
#include <stdarg.h>  // For va_list and related functions


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
    //server->paused = false;
    server->sequence = 0;
    //server->current_thread_id = 0;
    //server->current_line = 0;
    //    server->current_column = 0;
    //server->current_pc = 0;
    
    // Initialize the debugger state
    memset(&server->debugger_state, 0, sizeof(DebuggerState));

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

    // Initialize command callbacks array to NULL
    memset(server->command_callbacks, 0, sizeof(server->command_callbacks));
    
    // Initialize current command context
    memset(&server->current_command, 0, sizeof(server->current_command));
    server->current_command.type = DAP_CMD_INVALID;

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

    // Clean up debugger state
    cleanup_debugger_state(server);

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
 * @brief Clean up resources used by the current command context
 * 
 * This function should be called after a command and its implementation have completed
 * to free any dynamically allocated memory in the command context.
 * 
 * @param server The DAP server instance
 */
void cleanup_command_context(DAPServer *server)
{
    if (!server) {
        return;
    }
    
    // Clean up any resources in the command context based on command type
    switch (server->current_command.type) {
        case DAP_CMD_STEP_IN:
        case DAP_CMD_STEP_OUT:
        case DAP_CMD_NEXT:
            // Only free the granularity string if it's not the default static string "statement"
            if (server->current_command.context.step.granularity != NULL && 
                strcmp(server->current_command.context.step.granularity, "statement") != 0) {
                free((void*)server->current_command.context.step.granularity);
            }
            break;
            
        case DAP_CMD_SET_BREAKPOINTS:
            // Free source path and name
            if (server->current_command.context.breakpoint.source_path) {
                free((void*)server->current_command.context.breakpoint.source_path);
            }
            if (server->current_command.context.breakpoint.source_name) {
                free((void*)server->current_command.context.breakpoint.source_name);
            }
            // Free breakpoint arrays
            if (server->current_command.context.breakpoint.breakpoints) {
                free_breakpoints_array(server->current_command.context.breakpoint.breakpoints,
                                    server->current_command.context.breakpoint.breakpoint_count);
                server->current_command.context.breakpoint.breakpoints = NULL;
            }
            break;
            
        case DAP_CMD_SET_EXCEPTION_BREAKPOINTS:
            // Free filter arrays
            free_filter_arrays(server->current_command.context.exception.filters,
                             server->current_command.context.exception.conditions,
                             server->current_command.context.exception.filter_count);
            server->current_command.context.exception.filters = NULL;
            server->current_command.context.exception.conditions = NULL;
            break;
            
        case DAP_CMD_LAUNCH:
            // Free strings in launch context
            if (server->current_command.context.launch.program_path) {
                free((void*)server->current_command.context.launch.program_path);
            }
            if (server->current_command.context.launch.source_path) {
                free((void*)server->current_command.context.launch.source_path);
            }
            if (server->current_command.context.launch.map_path) {
                free((void*)server->current_command.context.launch.map_path);
            }
            if (server->current_command.context.launch.working_directory) {
                free((void*)server->current_command.context.launch.working_directory);
            }
            // Free command line arguments array
            if (server->current_command.context.launch.args) {
                for (int i = 0; i < server->current_command.context.launch.args_count; i++) {
                    free((void*)server->current_command.context.launch.args[i]);
                }
                free(server->current_command.context.launch.args);
            }
            break;
            
        case DAP_CMD_RESTART:
            // Free restart arguments if present
            if (server->current_command.context.restart.restart_args) {
                cJSON_Delete(server->current_command.context.restart.restart_args);
                server->current_command.context.restart.restart_args = NULL;
            }
            break;
            
        case DAP_CMD_DISASSEMBLE:
            // Free memory reference string
            if (server->current_command.context.disassemble.memory_reference) {
                free((void*)server->current_command.context.disassemble.memory_reference);
            }
            break;
            
        case DAP_CMD_READ_MEMORY:
            // Free memory reference string
            if (server->current_command.context.read_memory.memory_reference) {
                free((void*)server->current_command.context.read_memory.memory_reference);
            }
            break;
            
        case DAP_CMD_VARIABLES:
            // Free format string if set
            if (server->current_command.context.variables.format) {
                free((void*)server->current_command.context.variables.format);
            }
            break;
            
        case DAP_CMD_SET_VARIABLE:
            // Free dynamically allocated strings
            if (server->current_command.context.set_variable.name) {
                free((void*)server->current_command.context.set_variable.name);
            }
            if (server->current_command.context.set_variable.value) {
                free((void*)server->current_command.context.set_variable.value);
            }
            if (server->current_command.context.set_variable.format) {
                free((void*)server->current_command.context.set_variable.format);
            }
            break;
            
        default:
            // No cleanup needed for other command types
            break;
    }
    
    // Reset the command type to invalid to indicate context is clean
    server->current_command.type = DAP_CMD_INVALID;
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

    DAP_SERVER_DEBUG_LOG("Handling command: %d %s", (int)command, get_command_string(command));

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
    
    // Store command information for callbacks to access
    server->current_command.type = command;
    server->current_command.request_seq = response->request_seq;

    // Call protocol-level handler if available
    DAPCommandHandler command_handler = NULL;
    if (command >= 0 && command < DAP_CMD_MAX)
    {
        command_handler = server->command_handlers[command];
    }

    int result = -1;
    if (command_handler)
    {
        result = command_handler(server, json_args, response);
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
    
    // Clean up command context resources
    cleanup_command_context(server);

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
    int request_seq;
    cJSON *content = NULL;

    if (dap_parse_message(request, &type, &command, &request_seq, &content) < 0)
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
    
    // Store the request's sequence number in the response structure
    response.request_seq = request_seq;
    response.sequence = server->sequence++;
    // Call the appropriate command handler - dap_server_handle_command takes ownership of content
    // It will free content when done, so we don't need to free it here
    int result = dap_server_handle_command(server, command, NULL, content, &response);
    
    // Send the response with the same command type as the request
    if (result >= 0)
    {
        cJSON *response_body = response.data ? cJSON_Parse(response.data) : cJSON_CreateObject();
        dap_server_send_response(server, command, response.sequence, request_seq, response.success, response_body);
        //cJSON_Delete(response_body); (double free)
        
        // If this was an initialize request and it was successful, send the 'initialized' event
        if (command == DAP_CMD_INITIALIZE && response.success) {
            cJSON *event_body = cJSON_CreateObject();
            if (event_body) {
                // dap_server_send_event takes ownership of event_body and will free it
                dap_server_send_event(server, "initialized", event_body);
                // Don't delete event_body here - it's owned by dap_server_send_event

                // DEBUG, HACK!!
                // Send process event and thread event after initialized event
                // These events help clients proceed with the debug session                
                //dap_server_send_thread_event(server, "started", 1);
                //dap_server_send_process_event(server, "nd100x DAP", 1, true, "launch");
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
 * 4. Adds the provided body to the event
 * 5. Serializes and sends via transport
 *
 * @param server Server instance
 * @param event_type Event type as string (e.g., "initialized", "stopped", "output")
 * @param body Event body (JSON object) containing event-specific data
 * @return 0 on success, non-zero on failure
 * 
 * @note IMPORTANT: This function TAKES OWNERSHIP of the provided body.
 *       The caller should not access or free the body after calling this function.
 *       The body will be freed by this function when the event is deleted.
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

    // Add body if provided - take ownership of body parameter
    if (body)
    {
        // Add a reference to body rather than duplicating it
        cJSON_AddItemToObject(event, "body", body);
    }
    else
    {
        cJSON_AddObjectToObject(event, "body");
    }

    // Convert to string and send
    char *event_str = cJSON_PrintUnformatted(event);
    cJSON_Delete(event); // This will also free the body since we added the reference above
    
    if (!event_str)
    {
        dap_error_set(DAP_ERROR_MEMORY, "Failed to convert event to string");
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
 * @brief Initialize the command handlers array in the server struct
 * @param server Server instance to initialize handlers for
 */
void initialize_command_handlers(DAPServer *server) {
    // Clear the array first
    memset(server->command_handlers, 0, sizeof(server->command_handlers));
    
    // Also clear the command callbacks array
    memset(server->command_callbacks, 0, sizeof(server->command_callbacks));

    // Set up the handlers for each command type - explicitly listing all handlers
    // for better documentation and maintainability
    server->command_handlers[DAP_CMD_INITIALIZE] = &handle_initialize;
    server->command_handlers[DAP_CMD_LAUNCH] = &handle_launch;
    server->command_handlers[DAP_CMD_ATTACH] = &handle_attach;
    server->command_handlers[DAP_CMD_DISCONNECT] = &handle_disconnect;
    server->command_handlers[DAP_CMD_TERMINATE] = &handle_terminate;
    server->command_handlers[DAP_CMD_RESTART] = &handle_restart;
    server->command_handlers[DAP_CMD_SET_BREAKPOINTS] = &handle_set_breakpoints;
    server->command_handlers[DAP_CMD_CLEAR_BREAKPOINTS] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_SET_FUNCTION_BREAKPOINTS] = NULL;  // Not implemented
    server->command_handlers[DAP_CMD_SET_EXCEPTION_BREAKPOINTS] = &handle_set_exception_breakpoints;
    server->command_handlers[DAP_CMD_CONTINUE] = &handle_continue;
    server->command_handlers[DAP_CMD_NEXT] = &handle_next;
    server->command_handlers[DAP_CMD_STEP_IN] = &handle_step_in;
    server->command_handlers[DAP_CMD_STEP_OUT] = &handle_step_out;
    server->command_handlers[DAP_CMD_PAUSE] = &handle_pause;
    server->command_handlers[DAP_CMD_STACK_TRACE] = &handle_stack_trace;
    server->command_handlers[DAP_CMD_SCOPES] = &handle_scopes;
    server->command_handlers[DAP_CMD_VARIABLES] = &handle_variables;
    server->command_handlers[DAP_CMD_SET_VARIABLE] = &handle_set_variable;
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
 * @brief Register a command implementation callback
 * @param server Server instance
 * @param command_id Command ID to register the callback for
 * @param callback The implementation callback function
 * @return 0 on success, non-zero on failure
 */
int dap_server_register_command_callback(DAPServer *server, DAPCommandType command_id, DAPCommandCallback callback)
{
    if (!server || command_id < 0 || command_id >= DAP_CMD_MAX)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }
    

    // The key principle of memory management in the DAP server for callbacks are:
    //
    // Each function is responsible for cleaning up its own allocations
    // Callbacks only read data, they never free or take ownership
    // Memory is always freed whether callbacks succeed or fail
    // Helper functions for cleaning up complex data structures
    // This consistent approach will prevent memory leaks and ensure clear ownership boundaries between the DAP server and the mock debugger implementation.

    server->command_callbacks[command_id] = callback;
    return 0;
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
 * @param sequence Sequence number (unique for each request)
 * @param request_seq Sequence number from the request (must match the originating request)
 * @param success Whether the request was successfully processed
 * @param body Response body as a JSON object
 * @return int 0 on success, -1 on error
 * 
 * @note IMPORTANT: This function takes ownership of the body cJSON object and will free it.
 *       Do not access or free the body after calling this function.
 */
int dap_server_send_response(DAPServer *server, DAPCommandType command,
                             int sequence, int request_seq, bool success, cJSON *body)
{
    if (!server)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid server");
        return -1;
    }

    cJSON *response = dap_create_response(command, sequence, request_seq, success, body);
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
 * @brief Send a welcome message when a client connects
 * 
 * @param server The DAP server instance
 */
static void dap_server_send_welcome_message(DAPServer *server)
{
    if (!server) {
        return;
    }
        
    // Send an important welcome message
    dap_server_send_output_category(server, DAP_OUTPUT_IMPORTANT, "Connected to DAP debugger\n");
    
    // Also send a regular console message with version info
    dap_server_send_output_category(server, DAP_OUTPUT_CONSOLE, "Mock DAP server version 1.0\n");
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

        dap_server_send_welcome_message(server);

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


/**
 * @brief Send an output event to display text in the debug console
 * 
 * Creates and sends a properly formatted DAP output event to the client.
 * Output events are used to show text in the debug console of the IDE.
 * 
 * @param server Server instance
 * @param category Output category ("console", "stdout", "stderr", or "telemetry")
 * @param output The text content to display
 * @return 0 on success, non-zero on failure
 */
int dap_server_send_output_event(DAPServer *server, const char *category, const char *output)
{
    if (!server || !output)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    // Default category if not provided
    if (!category)
    {
        category = "console";
    }

    // Create output event body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        dap_error_set(DAP_ERROR_MEMORY, "Failed to create output event body");
        return -1;
    }

    // Add category and output to body
    cJSON_AddStringToObject(body, "category", category);
    cJSON_AddStringToObject(body, "output", output);

    // Send output event (function takes ownership of body)
    int result = dap_server_send_event(server, "output", body);
    
    return result;
}

/**
 * @brief Send an output message to the debug console
 * 
 * Simplified version of dap_server_send_output_event that uses "console" as the category.
 * Useful for quick debug messages or informational output.
 * 
 * @param server Server instance
 * @param message The message to display in the debug console
 * @return 0 on success, non-zero on failure
 */
int dap_server_send_output(DAPServer *server, const char *message)
{
    return dap_server_send_output_event(server, "console", message);
}

/**
 * @brief Send an output event with specified category using enum
 * 
 * Creates and sends an output event using a category specified by the DAPOutputCategory enum.
 * This is a convenience wrapper around dap_server_send_output_event that converts
 * the enum value to the corresponding string.
 * 
 * @param server Server instance
 * @param category Output category from DAPOutputCategory enum
 * @param output The text content to display
 * @return 0 on success, non-zero on failure
 */
int dap_server_send_output_category(DAPServer *server, DAPOutputCategory category, const char *output)
{
    if (!server || !output)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    // Convert enum to string category
    const char *category_str = NULL;
    switch (category) {
        case DAP_OUTPUT_CONSOLE:
            category_str = "console";
            break;
        case DAP_OUTPUT_STDOUT:
            category_str = "stdout";
            break;
        case DAP_OUTPUT_STDERR:
            category_str = "stderr";
            break;
        case DAP_OUTPUT_TELEMETRY:
            category_str = "telemetry";
            break;
        case DAP_OUTPUT_IMPORTANT:
            category_str = "important";
            break;
        case DAP_OUTPUT_PROGRESS:
            category_str = "progress";
            break;
        case DAP_OUTPUT_LOG:
            category_str = "log";
            break;
        default:
            category_str = "console"; // Default to console for unknown values
            break;
    }

    return dap_server_send_output_event(server, category_str, output);
}

/**
 * @brief Send a process event to the client
 * 
 * Creates and sends a process event to notify the client about a process.
 * This is typically sent after initialized event to indicate the debugger
 * has started a new process or attached to an existing one.
 * 
 * @param server Server instance
 * @param name Name of the process
 * @param system_process_id System process ID (0 if not applicable)
 * @param is_local_process Whether the process is local
 * @param start_method How the process was started ("launch", "attach", "attachForSuspendedLaunch")
 * @return 0 on success, non-zero on failure
 */
int dap_server_send_process_event(DAPServer *server, const char *name, int system_process_id, 
                                bool is_local_process, const char *start_method)
{
    if (!server || !name || !start_method)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    // Create process event body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        dap_error_set(DAP_ERROR_MEMORY, "Failed to create process event body");
        return -1;
    }

    // Add required fields
    cJSON_AddStringToObject(body, "name", name);
    cJSON_AddNumberToObject(body, "systemProcessId", system_process_id);
    cJSON_AddBoolToObject(body, "isLocalProcess", is_local_process);
    cJSON_AddStringToObject(body, "startMethod", start_method);
    
    // Send the process event (function takes ownership of body)
    return dap_server_send_event(server, "process", body);
}

/**
 * @brief Send a thread event to the client
 * 
 * Creates and sends a thread event to notify the client about thread status.
 * Used to indicate when a thread has started or exited.
 * 
 * @param server Server instance
 * @param reason The reason for the event ("started" or "exited")
 * @param thread_id The identifier of the thread
 * @return 0 on success, non-zero on failure
 */
int dap_server_send_thread_event(DAPServer *server, const char *reason, int thread_id)
{
    if (!server || !reason)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    // Create thread event body
    cJSON *body = cJSON_CreateObject();
    if (!body)
    {
        dap_error_set(DAP_ERROR_MEMORY, "Failed to create thread event body");
        return -1;
    }

    // Add required fields - the thread event requires both reason and threadId
    cJSON_AddStringToObject(body, "reason", reason);
    cJSON_AddNumberToObject(body, "threadId", thread_id);
    
    // Send the thread event (function takes ownership of body)
    return dap_server_send_event(server, "thread", body);
}


int dap_server_send_stopped_event(DAPServer *server, const char *reason, const char *description)
{
    if (!server || !reason)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }


    cJSON *event_body = cJSON_CreateObject();
    if (event_body) {        
        cJSON_AddNumberToObject(event_body, "threadId", server->debugger_state.current_thread_id);
        
        // REQUIRED by the spec!!!
        cJSON_AddStringToObject(event_body, "reason", reason);

        if (description) {
            // Add description
            cJSON_AddStringToObject(event_body, "description", description);
        }

        // Optional by the spec
        //      description?: string;             // OPTIONAL
        //      threadId?: number;                // OPTIONAL
        //      preserveFocusHint?: boolean;      // OPTIONAL
        //      text?: string;                    // OPTIONAL
        //      allThreadsStopped?: boolean;      // OPTIONAL
        //      hitBreakpointIds?: number[];      // OPTIONAL

        // Send the event
        dap_server_send_event(server, "stopped", event_body);

        return 0;
    }
    
    return -1;
}

/**
 * @brief Clean up resources used by the debugger state
 * 
 * This function handles the cleanup of all dynamically allocated memory
 * in the debugger_state structure. It should be called during server shutdown.
 * 
 * @param server The DAP server instance
 */
void cleanup_debugger_state(DAPServer *server)
{
    if (!server) return;
    
    // Helper macro to safely free pointers with valid memory address check
    #define SAFE_FREE(ptr) do { \
        if ((ptr) && (uintptr_t)(ptr) > 1024) { \
            DAP_SERVER_DEBUG_LOG("Freeing debugger state pointer %s at %p", #ptr, (void*)(ptr)); \
            free((void*)(ptr)); \
            (ptr) = NULL; \
        } \
    } while (0)
    
    // Free all dynamically allocated strings
    SAFE_FREE(server->debugger_state.program_path);
    SAFE_FREE(server->debugger_state.source_path);
    SAFE_FREE(server->debugger_state.map_path);
    SAFE_FREE(server->debugger_state.working_directory);
    SAFE_FREE(server->debugger_state.stop_reason);
    SAFE_FREE(server->debugger_state.stop_description);
    
    // Free command line arguments array if it exists
    if (server->debugger_state.args) {
        for (int i = 0; i < server->debugger_state.args_count; i++) {
            SAFE_FREE(server->debugger_state.args[i]);
        }
        free(server->debugger_state.args);
        server->debugger_state.args = NULL;
        server->debugger_state.args_count = 0;
    }
    
    // Free any user data if a cleanup function was provided
    if (server->debugger_state.user_data) {
        // If a custom cleanup function exists, it could be called here
        // For now, we're just nulling it out as we don't know how to free it
        server->debugger_state.user_data = NULL;
    }
    
    // Reset other state fields to default values
    server->debugger_state.program_counter = 0;
    server->debugger_state.source_line = 0;
    server->debugger_state.source_column = 0;
    server->debugger_state.current_thread_id = 0;
    server->debugger_state.has_stopped = false;
    server->debugger_state.no_debug = false;
    server->debugger_state.stop_at_entry = false;
    
    #undef SAFE_FREE
}



