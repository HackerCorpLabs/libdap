/**
 * @file dap_server.c
 * @brief Server implementation for the DAP library
 */

#include "dap_server.h"
#include "dap_error.h"
#include "dap_types.h"
#include "dap_transport.h"
#include "dap_protocol.h"
#include <cjson/cJSON.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>


// Debug logging macro
#define DAP_SERVER_DEBUG_LOG(...) do { \
    fprintf(stderr, "[DAP SERVER %s:%d] ", __func__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
    fflush(stderr); \
} while(0)


#include "dap_types.h"
#include <cjson/cJSON.h>



void cleanup_breakpoints(DAPServer* dap_server) {
    if (dap_server->breakpoints) {
        for (int i = 0; i < dap_server->breakpoint_count; i++) {
            if (dap_server->breakpoints[i].source) {
                free(dap_server->breakpoints[i].source->path);
                free(dap_server->breakpoints[i].source);
            }
        }
        free(dap_server->breakpoints);
        dap_server->breakpoints = NULL;
        dap_server->breakpoint_count = 0;
    }
}



void cleanup_line_maps(DAPServer* dap_server) {
    if (dap_server->line_maps) {
        for (int i = 0; i < dap_server->line_map_count; i++) {
            free((void*)dap_server->line_maps[i].file_path);
        }
        free(dap_server->line_maps);
        dap_server->line_maps = NULL;
        dap_server->line_map_count = 0;
        dap_server->line_map_capacity = 0;
    }
}


// Server state
typedef struct {
    DAPServer* server;
    bool is_connected;
    bool is_running;
    bool is_paused;
    int current_thread_id;
    DAPEventType last_event;  // Track last event type
} DAPServerState;

DAPServer* dap_server_create(const DAPServerConfig* config) {
    if (!config) {
        return NULL;
    }

    DAPServer* server = calloc(1, sizeof(DAPServer));
    if (!server) {
        return NULL;
    }

    if (dap_server_init(server, config) < 0) {
        free(server);
        return NULL;
    }

    return server;
}

int dap_server_init(DAPServer* server, const DAPServerConfig* config) {
    if (!server || !config) {
        return -1;
    }

    server->transport = dap_transport_create(&config->transport);
    if (!server->transport) {
        return -1;
    }

    memcpy(&server->config, config, sizeof(DAPServerConfig));
    server->is_initialized = true;
    server->is_running = false;
    server->sequence = 0;
    server->current_thread_id = 0;

    return 0;
}

/**
 * @brief Start the DAP server
 * 
 * @param server Server instance
 * @return int 0 on success, -1 on error
 */
int dap_server_start(DAPServer* server) {
    if (!server) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid server");
        return -1;
    }

    if (dap_transport_start(server->transport) < 0) {
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
int dap_server_stop(DAPServer* server) {
    if (!server) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid server");
        return -1;
    }

    if (dap_transport_stop(server->transport) < 0) {
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
void dap_server_free(DAPServer* server) {
    if (!server) return;

    if (server->transport) {
        dap_transport_free(server->transport);
    }

    if (server->config.program_path) {
        free(server->config.program_path);
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
int dap_server_process_message(DAPServer* server, const char* message) {
    if (!server || !message) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    // Parse message
    DAPMessageType type;
    DAPCommandType command;
    int sequence;
    cJSON* content = NULL;
    
    if (dap_parse_message(message, &type, &command, &sequence, &content) < 0) {
        return -1;
    }

    switch (type) {
        case DAP_MESSAGE_REQUEST:
            // Handle request
            if (dap_server_handle_request(server, command, sequence, content) < 0) {
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
            DAP_SERVER_DEBUG_LOG("Received event: type=%d", command);
            if (server->config.callbacks.handle_event) {
                char* content_str = cJSON_PrintUnformatted(content);
                server->config.callbacks.handle_event(server->config.user_data, (DAPEventType)command, content_str);
                free(content_str);
            }
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
int dap_server_send_response(DAPServer* server, DAPCommandType command,
                           int sequence, bool success, cJSON* body) {
    if (!server) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid server");
        return -1;
    }

    cJSON* response = dap_create_response(command, sequence, success, body);
    if (!response) {
        return -1;
    }

    char* response_str = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    
    if (!response_str) {
        return -1;
    }

    if (dap_transport_send(server->transport, response_str) < 0) {
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
int dap_server_send_event(DAPServer* server, DAPEventType event_type, cJSON* body) {
    if (!server) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid server");
        return -1;
    }

    cJSON* event = dap_create_event(event_type, body);
    if (!event) {
        return -1;
    }

    char* event_str = cJSON_PrintUnformatted(event);
    cJSON_Delete(event);
    
    if (!event_str) {
        return -1;
    }

    if (dap_transport_send(server->transport, event_str) < 0) {
        dap_error_set(DAP_ERROR_TRANSPORT, "Failed to send event");
        free(event_str);
        return -1;
    }

    free(event_str);
    return 0;
}

int dap_server_handle_request(DAPServer* server, DAPCommandType command,
                            int sequence, cJSON* content) {
    if (!server) {
        DAP_SERVER_DEBUG_LOG("Invalid server pointer");
        dap_error_set(DAP_ERROR_INVALID_STATE, "Server not properly initialized");
        return -1;
    }

    DAP_SERVER_DEBUG_LOG("Handling request: command=%d, sequence=%d", command, sequence);
    if (content) {
        char* content_str = cJSON_PrintUnformatted(content);
        DAP_SERVER_DEBUG_LOG("Request content: %s", content_str);
        free(content_str);
    }

    // Check if we have a callback
    if (!server->config.callbacks.handle_command) {
        DAP_SERVER_DEBUG_LOG("No command handler registered");
        cJSON* error_response = cJSON_CreateObject();
        cJSON* error = cJSON_CreateObject();
        cJSON_AddNumberToObject(error, "id", 1000);
        cJSON_AddStringToObject(error, "format", "No command handler registered");
        cJSON_AddBoolToObject(error, "showUser", true);
        cJSON_AddItemToObject(error_response, "error", error);
        return dap_server_send_response(server, command, sequence, false, error_response);
    }

    // Create response structure
    DAPResponse response = {0};
    
    // Convert content to string for callback
    char* content_str = content ? cJSON_PrintUnformatted(content) : NULL;
    
    // Call the handler
    int result = server->config.callbacks.handle_command(server->config.user_data, 
                                                       command, 
                                                       content_str,
                                                       &response);
    
    if (content_str) {
        free(content_str);
    }
    
    if (result < 0) {
        dap_error_set(DAP_ERROR_REQUEST_FAILED, "Command handler failed");
        if (response.error_message) {
            free(response.error_message);
        }
        if (response.data) {
            free(response.data);
        }
        return -1;
    }

    // Send the response with the same command type as the request
    cJSON* response_body = response.data ? cJSON_Parse(response.data) : cJSON_CreateObject();
    result = dap_server_send_response(server, command, sequence, 
                                    response.success, 
                                    response_body);

    // Clean up response
    if (response.error_message) {
        free(response.error_message);
    }
    if (response.data) {
        free(response.data);
    }

    return result;
}




int dap_server_run(DAPServer* server) {
    if (!server) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid server");
        return -1;
    }

    if (!server->is_initialized) {
        dap_error_set(DAP_ERROR_INVALID_STATE, "Server not initialized");
        return -1;
    }

    while (server->is_running) {
        if (dap_transport_accept(server->transport) < 0) {
            continue;
        }

        while (server->is_running) {
            char* message = NULL;
            int result = dap_transport_receive(server->transport, &message);
            if (result < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                break;
            }

            if (!message) {
                break;
            }

            if (dap_server_process_message(server, message) < 0) {
                free(message);
                continue;
            }

            free(message);
        }
    }

    return 0;
} 




// Update add_breakpoint to use MockDebugger
void add_breakpoint(DAPServer* server, const char* file_path, int line) {
    // Check if breakpoint already exists
    for (int i = 0; i < server->breakpoint_count; i++) {
        if (server->breakpoints[i].source && 
            strcmp(server->breakpoints[i].source->path, file_path) == 0 && 
            server->breakpoints[i].line == line) {
            return; // Breakpoint already exists
        }
    }

    // Resize array if needed
    if (server->breakpoint_count >= MAX_BREAKPOINTS) {
        return;
    }

    DAPBreakpoint* new_breakpoints = realloc(server->breakpoints, 
                                           (server->breakpoint_count + 1) * sizeof(DAPBreakpoint));
    if (!new_breakpoints) {
        return;
    }

    server->breakpoints = new_breakpoints;
    server->breakpoints[server->breakpoint_count].line = line;
    server->breakpoints[server->breakpoint_count].column = 0;
    server->breakpoints[server->breakpoint_count].verified = true;
    
    // Set the source
    DAPSource* bp_source = malloc(sizeof(DAPSource));
    if (bp_source) {
        bp_source->path = strdup(file_path);
        server->breakpoints[server->breakpoint_count].source = bp_source;
    }
    
    server->breakpoint_count++;
}

// Update remove_breakpoints to use MockDebugger
void remove_breakpoints(DAPServer* server, const char* file_path) {
    for (int i = 0; i < server->breakpoint_count; i++) {
        if (server->breakpoints[i].source && 
            strcmp(server->breakpoints[i].source->path, file_path) == 0) {
            // Free the source
            if (server->breakpoints[i].source) {
                free(server->breakpoints[i].source->path);
                free(server->breakpoints[i].source);
            }
            
            // Move last breakpoint to this position
            if (i < server->breakpoint_count - 1) {
                server->breakpoints[i] = server->breakpoints[server->breakpoint_count - 1];
            }
            server->breakpoint_count--;
            i--; // Check this position again
        }
    }
}

// Update get_breakpoints_for_file to use MockDebugger
cJSON* get_breakpoints_for_file(DAPServer* server, const char* file_path) {
    cJSON* breakpoints = cJSON_CreateArray();
    if (!breakpoints) return NULL;

    for (int i = 0; i < server->breakpoint_count; i++) {
        if (server->breakpoints[i].source && 
            strcmp(server->breakpoints[i].source->path, file_path) == 0) {
            cJSON* bp = cJSON_CreateObject();
            if (bp) {
                cJSON_AddNumberToObject(bp, "line", server->breakpoints[i].line);
                cJSON_AddBoolToObject(bp, "verified", server->breakpoints[i].verified);
                cJSON_AddItemToArray(breakpoints, bp);
            }
        }
    }

    return breakpoints;
}

// Add helper function for line mapping
int get_line_for_address(DAPServer* server, uint32_t address) {
    for (int i = 0; i < server->line_map_count; i++) {
        if (server->line_maps[i].address == address) {
            return server->line_maps[i].line;
        }
    }
    return -1;
}

// Fix pointer type in add_line_map
void add_line_map(DAPServer* server, const char* file_path, int line, uint32_t address) {
    if (server->line_map_count >= server->line_map_capacity) {
        size_t new_capacity = server->line_map_capacity == 0 ? 16 : server->line_map_capacity * 2;
        SourceLineMap* new_maps = realloc(server->line_maps, new_capacity * sizeof(SourceLineMap));
        if (!new_maps) {
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

