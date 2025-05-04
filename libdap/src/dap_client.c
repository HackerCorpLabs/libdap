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

/**
 * @file dap_client.c
 * @brief DAP client implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <stdbool.h>
#include <poll.h>
#include <cjson/cJSON.h>
#include <assert.h>

#include "dap_client.h"
#include "dap_protocol.h"
#include "dap_message.h"
#include "dap_transport.h"
#include "dap_types.h"
#include "dap_error.h"

// Debug logging macro
#define DAP_CLIENT_DEBUG_LOG(...) do { \
    fprintf(stderr, "[DAP Client %s:%d] ", __func__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
    fflush(stderr); \
} while(0)

// Add debug logging function
static void dap_debug_log_message(DAPClient* client, const char* prefix, const char* message) {
    if (client->debug_mode) {
        fprintf(stderr, "[DAP DEBUG] %s: %s\n", prefix, message);
    }
}

/**
 * @brief Send a message to the DAP server and wait for response
 * 
 * @param client Pointer to the client
 * @param message_str The message to send
 * @param response_body Output parameter for response body (caller must free)
 * @return int 0 on success, -1 on failure
 */
int dap_client_send_message(DAPClient* client, const char* message_str, char** response_body) {
    if (!client || !message_str) {
        DAP_CLIENT_DEBUG_LOG("Invalid arguments");
        return -1;
    }
    
    // Check if client is connected
    if (!client->connected || !client->transport) {
        DAP_CLIENT_DEBUG_LOG("Client not connected");
        return -1;
    }

    dap_debug_log_message(client, "Send", message_str);

    // Send message using transport layer
    if (dap_transport_send(client->transport, message_str) != 0) {
        DAP_CLIENT_DEBUG_LOG("Failed to send message");
        return -1;
    }

    // Wait for response with timeout
    struct pollfd pfd = {
        .fd = client->transport->client_fd,
        .events = POLLIN
    };

    int poll_result = poll(&pfd, 1, client->timeout_ms);
    if (poll_result < 0) {
        DAP_CLIENT_DEBUG_LOG("Poll failed: %s", strerror(errno));
        return -1;
    } else if (poll_result == 0) {
        DAP_CLIENT_DEBUG_LOG("Timeout waiting for response");
        return -1;
    }

    // Read response using transport layer, handling any events that arrive first
    char* response = NULL;
    while (1) {
        char* message = NULL;
        if (dap_transport_receive(client->transport, &message) != 0) {
            DAP_CLIENT_DEBUG_LOG("Failed to receive message");
            return -1;
        }
        
        if (!message) {
            DAP_CLIENT_DEBUG_LOG("Received null message");
            return -1;
        }
        
        // Parse the message to determine if it's a response or an event
        cJSON* json = cJSON_Parse(message);
        if (!json) {
            DAP_CLIENT_DEBUG_LOG("Failed to parse message as JSON: %s", message);
            free(message);
            return -1;
        }
        
        // Check the message type
        cJSON* type_obj = cJSON_GetObjectItem(json, "type");
        if (!type_obj || !cJSON_IsString(type_obj)) {
            DAP_CLIENT_DEBUG_LOG("Message missing 'type' field: %s", message);
            cJSON_Delete(json);
            free(message);
            return -1;
        }
        
        const char* type = type_obj->valuestring;
        
        // If it's an event, process it and continue waiting for response
        if (strcmp(type, "event") == 0) {
            // Process event (log it for now)
            cJSON* event_obj = cJSON_GetObjectItem(json, "event");
            if (event_obj && cJSON_IsString(event_obj)) {
                DAP_CLIENT_DEBUG_LOG("Received event while waiting for response: %s", event_obj->valuestring);
                
                // Here you could add more sophisticated event handling
                // For example, store the event in a queue for later processing
                // or call an event handler callback if one is registered
            }
            
            // Use the common event handler
            dap_client_handle_event(client, json);
            
            cJSON_Delete(json);
            free(message);
            continue; // Continue waiting for response
        } 
        // If it's a response, break the loop and return it
        else if (strcmp(type, "response") == 0) {
            response = message; // Store the response
            cJSON_Delete(json);
            break;
        } 
        // Unknown message type
        else {
            DAP_CLIENT_DEBUG_LOG("Unexpected message type: %s", type);
            cJSON_Delete(json);
            free(message);
            return -1;
        }
    }

    // Allocate and copy response
    if (response_body) {
        *response_body = response;
    } else {
        free(response);
    }

    if (response_body && *response_body) {
        dap_debug_log_message(client, "Receive", *response_body);
    }

    return 0;
}

/**
 * @brief Send a DAP request and wait for response
 * 
 * @param client Pointer to the client
 * @param command Command type
 * @param arguments Request arguments (cJSON object, may be NULL)
 * @param response_body Output parameter for response body (caller must free)
 * @return int 0 on success, -1 on failure
 */
int dap_client_send_request(DAPClient* client, DAPCommandType command, cJSON* arguments, char** response_body) {
    if (!client) {
        DAP_CLIENT_DEBUG_LOG("Client is NULL");
        return -1;
    }
    
    if (!client->connected || !client->transport) {
        DAP_CLIENT_DEBUG_LOG("Client not connected");
        return -1;
    }

    // Create request object
    cJSON* request = cJSON_CreateObject();
    if (!request) {
        DAP_CLIENT_DEBUG_LOG("Failed to create request object");
        return -1;
    }

    // Add required fields according to DAP specification
    cJSON_AddStringToObject(request, "type", "request");
    cJSON_AddNumberToObject(request, "seq", client->seq++);
    cJSON_AddStringToObject(request, "command", get_command_string(command));
    
    // Add arguments if provided
    if (arguments) {
        cJSON_AddItemToObject(request, "arguments", cJSON_Duplicate(arguments, true));
    }

    // Serialize request
    char* message_str = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);
    if (!message_str) {
        DAP_CLIENT_DEBUG_LOG("Failed to serialize request");
        return -1;
    }

    // Log request if debug mode is enabled
    dap_debug_log_message(client, "Sending request", message_str);

    // Send message
    int result = dap_client_send_message(client, message_str, response_body);
    free(message_str);

    // Log response if debug mode is enabled and we got one
    if (result == 0 && response_body && *response_body) {
        dap_debug_log_message(client, "Received response", *response_body);
    }

    return result;
}

/**
 * @brief Create a new DAP client
 * 
 * @param host Server hostname
 * @param port Server port number
 * @return DAPClient* Pointer to the created client, NULL on failure
 */
DAPClient* dap_client_create(const char* host, int port) {
    if (!host || port <= 0) {
        DAP_CLIENT_DEBUG_LOG("Invalid arguments");
        return NULL;
    }

    DAPClient* client = (DAPClient*)malloc(sizeof(DAPClient));
    if (!client) {
        DAP_CLIENT_DEBUG_LOG("Failed to allocate memory for client");
        return NULL;
    }

    client->host = strdup(host);
    if (!client->host) {
        DAP_CLIENT_DEBUG_LOG("Failed to allocate memory for host");
        free(client);
        return NULL;
    }

    client->port = port;
    client->fd = -1;  // Will be deprecated, but kept for backward compatibility
    client->connected = false;
    client->timeout_ms = 5000; // Default 5 second timeout
    client->seq = 1;
    client->thread_id = -1;  // Initialize to invalid thread ID
    client->debug_mode = false;  // Debug mode off by default
    
    // Initialize breakpoints tracking
    client->breakpoints = NULL;
    client->num_breakpoints = 0;
    
    // Create transport configuration
    DAPTransportConfig transport_config = {
        .type = DAP_TRANSPORT_TCP,
        .config.tcp = {
            .host = host,
            .port = port
        }
    };
    
    // Create transport
    client->transport = dap_transport_create(&transport_config);
    if (!client->transport) {
        DAP_CLIENT_DEBUG_LOG("Failed to create transport");
        free(client->host);
        free(client);
        return NULL;
    }
    
    // Client transport should not be in server mode
    client->transport->is_server = false;

    return client;
}

/**
 * @brief Connect to a DAP server
 * 
 * @param client Pointer to the client
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_connect(DAPClient* client) {
    if (!client) {
        DAP_CLIENT_DEBUG_LOG("Invalid client pointer");
        return -1;
    }

    if (client->connected) {
        DAP_CLIENT_DEBUG_LOG("Client is already connected");
        return -1;
    }

    // Create socket using the transport layer
    if (dap_transport_connect(client->transport) != 0) {
        DAP_CLIENT_DEBUG_LOG("Failed to connect to server");
        return -1;
    }

    // Store the socket descriptor for backward compatibility
    client->fd = client->transport->client_fd;
    client->connected = true;
    
    DAP_CLIENT_DEBUG_LOG("Connected to server at %s:%d", client->host, client->port);
    return 0;
}

/**
 * @brief Disconnect from a DAP server
 * 
 * @param client Pointer to the client
 * @param restart Whether to restart the debuggee
 * @param terminate_debuggee Whether to terminate the debuggee
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_disconnect(DAPClient* client, bool restart, bool terminate_debuggee, DAPDisconnectResult* result) {
    if (!client || !result) {
        return DAP_ERROR_INVALID_ARG;
    }
    
    // Check if already disconnected to prevent double disconnect
    if (!client->connected) {
        result->base.success = true;
        result->restart = restart;
        result->terminate_debuggee = terminate_debuggee;
        return DAP_ERROR_NONE;
    }
    
    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }
    cJSON_AddBoolToObject(args, "restart", restart);
    cJSON_AddBoolToObject(args, "terminate_debuggee", terminate_debuggee);
    char* response_body = NULL;
    int error = dap_client_send_request(client, DAP_CMD_DISCONNECT, args, &response_body);
    cJSON_Delete(args);
    if (response_body) {
        free(response_body);
    }
    
    // Mark as disconnected regardless of whether the disconnect request succeeded
    client->connected = false;
    
    if (error == DAP_ERROR_NONE) {
        result->base.success = true;
        result->restart = restart;
        result->terminate_debuggee = terminate_debuggee;
        return DAP_ERROR_NONE;
    }
    return error;
}

/**
 * @brief Free a DAP client
 * 
 * @param client Pointer to the client
 */
void dap_client_free(DAPClient* client) {
    if (!client) return;
    
    // Set a flag to avoid any use of the client during freeing
    client->connected = false;
    
    // Free transport if it exists
    if (client->transport) {
        dap_transport_free(client->transport);
        client->transport = NULL;
    }
    
    // Free hostname if it exists
    if (client->host) {
        free(client->host);
        client->host = NULL;
    }
    
    // Free program path if it exists
    if (client->program_path) {
        free(client->program_path);
        client->program_path = NULL;
    }
    
    // Free breakpoints if they exist
    if (client->breakpoints) {
        // Free any dynamically allocated fields within breakpoints
        for (int i = 0; i < client->num_breakpoints; i++) {
            if (client->breakpoints[i].message) {
                free(client->breakpoints[i].message);
            }
            if (client->breakpoints[i].condition) {
                free(client->breakpoints[i].condition);
            }
            // Free any other fields that might be dynamically allocated
        }
        free(client->breakpoints);
        client->breakpoints = NULL;
    }
    
    // Free client structure
    free(client);
}

/**
 * @brief Get source content
 * 
 * @param client Pointer to the client
 * @param source_path Source file path
 * @param source_reference Source reference
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_source(DAPClient* client, const char* source_path, int source_reference, DAPSourceResult* result) {
    if (!client || !result) {
        return DAP_ERROR_INVALID_ARG;
    }
    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }
    if (source_path) {
        cJSON* source = cJSON_CreateObject();
        if (!source) {
            cJSON_Delete(args);
            return DAP_ERROR_MEMORY;
        }
        cJSON_AddStringToObject(source, "path", source_path);
        cJSON_AddItemToObject(args, "source", source);
    } else if (source_reference > 0) {
        cJSON_AddNumberToObject(args, "sourceReference", source_reference);
    } else {
        cJSON_Delete(args);
        return DAP_ERROR_INVALID_ARG;
    }
    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_SOURCE, args, &response);
    cJSON_Delete(args);
    if (error != DAP_ERROR_NONE) {
        return error;
    }
    if (!response) {
        return DAP_ERROR_PARSE_ERROR;
    }
    cJSON* root = cJSON_Parse(response);
    free(response);
    if (!root) {
        return DAP_ERROR_PARSE_ERROR;
    }
    cJSON* body = cJSON_GetObjectItem(root, "body");
    if (!body) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }
    cJSON* content = cJSON_GetObjectItem(body, "content");
    if (!content || !cJSON_IsString(content)) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }
    result->content = strdup(content->valuestring);
    if (!result->content) {
        cJSON_Delete(root);
        return DAP_ERROR_MEMORY;
    }
    cJSON* mime_type = cJSON_GetObjectItem(body, "mimeType");
    if (mime_type && cJSON_IsString(mime_type)) {
        result->mime_type = strdup(mime_type->valuestring);
        if (!result->mime_type) {
            free(result->content);
            cJSON_Delete(root);
            return DAP_ERROR_MEMORY;
        }
    } else {
        result->mime_type = NULL;
    }
    cJSON_Delete(root);
    return DAP_ERROR_NONE;
}

/**
 * @brief Parse a setBreakpoints response from JSON
 * 
 * @param response Response string from the server
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_json_parse_set_breakpoints_response(const char* response, DAPSetBreakpointsResult* result) {
    if (!response || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    cJSON* root = cJSON_Parse(response);
    if (!root) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* body = cJSON_GetObjectItem(root, "body");
    if (!body) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* result_bps = cJSON_GetObjectItem(body, "breakpoints");
    if (!result_bps || !cJSON_IsArray(result_bps)) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    result->num_breakpoints = cJSON_GetArraySize(result_bps);
    result->breakpoints = malloc(result->num_breakpoints * sizeof(DAPBreakpoint));
    if (!result->breakpoints) {
        cJSON_Delete(root);
        return DAP_ERROR_MEMORY;
    }

    for (size_t i = 0; i < result->num_breakpoints; i++) {
        cJSON* bp = cJSON_GetArrayItem(result_bps, i);
        if (!bp) {
            for (size_t j = 0; j < i; j++) {
                free(result->breakpoints[j].condition);
                free(result->breakpoints[j].message);
            }
            free(result->breakpoints);
            cJSON_Delete(root);
            return DAP_ERROR_PARSE_ERROR;
        }

        cJSON* id = cJSON_GetObjectItem(bp, "id");
        cJSON* verified = cJSON_GetObjectItem(bp, "verified");
        cJSON* line = cJSON_GetObjectItem(bp, "line");
        cJSON* message = cJSON_GetObjectItem(bp, "message");

        result->breakpoints[i].id = id ? id->valueint : 0;
        result->breakpoints[i].verified = verified ? verified->valueint : false;
        result->breakpoints[i].line = line ? line->valueint : 0;
        result->breakpoints[i].message = message ? strdup(message->valuestring) : NULL;
        if (message && !result->breakpoints[i].message) {
            for (size_t j = 0; j < i; j++) {
                free(result->breakpoints[j].condition);
                free(result->breakpoints[j].message);
            }
            free(result->breakpoints);
            cJSON_Delete(root);
            return DAP_ERROR_MEMORY;
        }
        
        // Initialize other fields to NULL or default values
        result->breakpoints[i].condition = NULL;
        result->breakpoints[i].hit_condition = NULL;
        result->breakpoints[i].log_message = NULL;
        result->breakpoints[i].source = NULL;
    }

    cJSON_Delete(root);
    return DAP_ERROR_NONE;
}

/**
 * @brief Set breakpoints in a source file
 * 
 * @param client Pointer to the client
 * @param source_path Source file path
 * @param breakpoints Array of breakpoints
 * @param num_breakpoints Number of breakpoints
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_set_breakpoints(DAPClient* client, const char* source_path, 
                             const DAPSourceBreakpoint* breakpoints, size_t num_breakpoints,
                             DAPSetBreakpointsResult* result) {
    if (!client || !source_path || !breakpoints || num_breakpoints == 0 || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    cJSON* source = cJSON_CreateObject();
    if (!source) {
        cJSON_Delete(args);
        return DAP_ERROR_MEMORY;
    }
    cJSON_AddStringToObject(source, "path", source_path);
    cJSON_AddItemToObject(args, "source", source);

    cJSON* bps = cJSON_CreateArray();
    if (!bps) {
        cJSON_Delete(args);
        return DAP_ERROR_MEMORY;
    }

    for (size_t i = 0; i < num_breakpoints; i++) {
        cJSON* bp = cJSON_CreateObject();
        if (!bp) {
            cJSON_Delete(args);
            return DAP_ERROR_MEMORY;
        }
        cJSON_AddNumberToObject(bp, "line", breakpoints[i].line);
        if (breakpoints[i].column > 0) {
            cJSON_AddNumberToObject(bp, "column", breakpoints[i].column);
        }
        if (breakpoints[i].condition) {
            cJSON_AddStringToObject(bp, "condition", breakpoints[i].condition);
        }
        cJSON_AddItemToArray(bps, bp);
    }
    cJSON_AddItemToObject(args, "breakpoints", bps);

    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_SET_BREAKPOINTS, args, &response);
    cJSON_Delete(args);
    
    if (error != DAP_ERROR_NONE) {
        return error;
    }

    // Parse response
    error = dap_json_parse_set_breakpoints_response(response, result);
    free(response);
    
    if (error == DAP_ERROR_NONE) {
        // Update client's breakpoint tracking
        error = dap_client_update_breakpoints(client, source_path, result->breakpoints, result->num_breakpoints);
    }
    
    return error;
}

/**
 * @brief Free a DAPModulesResult structure
 * 
 * @param result The result structure to free
 */
void dap_modules_result_free(DAPModulesResult* result) {
    if (!result) {
        return;
    }

    if (result->modules) {
        for (size_t i = 0; i < result->num_modules; i++) {
            free(result->modules[i].id);
            free(result->modules[i].name);
            free(result->modules[i].path);
            free(result->modules[i].version);
            free(result->modules[i].symbol_status);
            free(result->modules[i].symbol_file_path);
            free(result->modules[i].date_time_stamp);
            free(result->modules[i].address_range);
        }
        free(result->modules);
    }

    result->modules = NULL;
    result->num_modules = 0;
}

/**
 * @brief Parse a DAPSource from JSON
 * 
 * @param json The JSON object to parse
 * @return DAPSource* The parsed source, or NULL on error
 */
DAPSource* dap_source_parse(cJSON* json) {
    if (!json) {
        return NULL;
    }
    DAPSource* source = calloc(1, sizeof(DAPSource));
    if (!source) {
        return NULL;
    }
    cJSON* name = cJSON_GetObjectItem(json, "name");
    cJSON* path = cJSON_GetObjectItem(json, "path");
    cJSON* source_reference = cJSON_GetObjectItem(json, "sourceReference");
    cJSON* presentation_hint = cJSON_GetObjectItem(json, "presentationHint");
    cJSON* origin = cJSON_GetObjectItem(json, "origin");
    cJSON* sources = cJSON_GetObjectItem(json, "sources");
    cJSON* adapter_data = cJSON_GetObjectItem(json, "adapterData");
    cJSON* checksums = cJSON_GetObjectItem(json, "checksums");
    if (name && cJSON_IsString(name)) {
        source->name = strdup(name->valuestring);
    }
    if (path && cJSON_IsString(path)) {
        source->path = strdup(path->valuestring);
    }
    if (source_reference && cJSON_IsNumber(source_reference)) {
        source->source_reference = source_reference->valueint;
    }
    if (presentation_hint && cJSON_IsString(presentation_hint)) {
        if (strcmp(presentation_hint->valuestring, "normal") == 0) {
            source->presentation_hint = DAP_SOURCE_PRESENTATION_NORMAL;
        } else if (strcmp(presentation_hint->valuestring, "emphasize") == 0) {
            source->presentation_hint = DAP_SOURCE_PRESENTATION_EMPHASIZE;
        } else if (strcmp(presentation_hint->valuestring, "deemphasize") == 0) {
            source->presentation_hint = DAP_SOURCE_PRESENTATION_DEEMPHASIZE;
        }
    }
    if (origin && cJSON_IsString(origin)) {
        if (strcmp(origin->valuestring, "generated") == 0) {
            source->origin = DAP_SOURCE_ORIGIN_GENERATED;
        } else if (strcmp(origin->valuestring, "deployed") == 0) {
            source->origin = DAP_SOURCE_ORIGIN_DEPLOYED;
        } else {
            source->origin = DAP_SOURCE_ORIGIN_UNKNOWN;
        }
    }
    if (adapter_data && cJSON_IsString(adapter_data)) {
        source->adapter_data = strdup(adapter_data->valuestring);
    }
    if (sources && cJSON_IsArray(sources)) {
        int num_sources = cJSON_GetArraySize(sources);
        source->sources = calloc(num_sources, sizeof(DAPSource));
        if (source->sources) {
            source->num_sources = num_sources;
            for (int i = 0; i < num_sources; i++) {
                cJSON* sub_source = cJSON_GetArrayItem(sources, i);
                if (sub_source) {
                    DAPSource* parsed = dap_source_parse(sub_source);
                    if (parsed) {
                        source->sources[i] = *parsed;
                        free(parsed);
                    }
                }
            }
        }
    }
    if (checksums && cJSON_IsArray(checksums)) {
        int num_checksums = cJSON_GetArraySize(checksums);
        source->checksums = calloc(num_checksums, sizeof(DAPChecksum));
        if (source->checksums) {
            source->num_checksums = num_checksums;
            for (int i = 0; i < num_checksums; i++) {
                cJSON* checksum = cJSON_GetArrayItem(checksums, i);
                if (checksum) {
                    cJSON* algorithm = cJSON_GetObjectItem(checksum, "algorithm");
                    cJSON* checksum_value = cJSON_GetObjectItem(checksum, "checksum");
                    if (algorithm && cJSON_IsString(algorithm) && checksum_value && cJSON_IsString(checksum_value)) {
                        if (strcmp(algorithm->valuestring, "MD5") == 0) {
                            source->checksums[i].algorithm = DAP_CHECKSUM_MD5;
                        } else if (strcmp(algorithm->valuestring, "SHA1") == 0) {
                            source->checksums[i].algorithm = DAP_CHECKSUM_SHA1;
                        } else if (strcmp(algorithm->valuestring, "SHA256") == 0) {
                            source->checksums[i].algorithm = DAP_CHECKSUM_SHA256;
                        } else {
                            source->checksums[i].algorithm = DAP_CHECKSUM_MD5; // default or error value
                        }
                        source->checksums[i].checksum = strdup(checksum_value->valuestring);
                    }
                }
            }
        }
    }
    return source;
}

int dap_client_modules(DAPClient* client, int start_module, int module_count, DAPModulesResult* result) {
    if (!client || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    if (start_module >= 0) {
        cJSON_AddNumberToObject(args, "startModule", start_module);
    }
    if (module_count > 0) {
        cJSON_AddNumberToObject(args, "moduleCount", module_count);
    }

    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_MODULES, args, &response);
    cJSON_Delete(args);

    if (error != DAP_ERROR_NONE) {
        return error;
    }

    if (!response) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* root = cJSON_Parse(response);
    free(response);

    if (!root) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* body = cJSON_GetObjectItem(root, "body");
    if (!body) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* modules = cJSON_GetObjectItem(body, "modules");
    if (!modules || !cJSON_IsArray(modules)) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    int num_modules = cJSON_GetArraySize(modules);
    result->modules = calloc(num_modules, sizeof(DAPModule));
    if (!result->modules) {
        cJSON_Delete(root);
        return DAP_ERROR_MEMORY;
    }

    result->num_modules = num_modules;

    for (int i = 0; i < num_modules; i++) {
        cJSON* module = cJSON_GetArrayItem(modules, i);
        if (!module) {
            dap_modules_result_free(result);
            cJSON_Delete(root);
            return DAP_ERROR_PARSE_ERROR;
        }

        cJSON* id = cJSON_GetObjectItem(module, "id");
        cJSON* name = cJSON_GetObjectItem(module, "name");
        cJSON* path = cJSON_GetObjectItem(module, "path");
        cJSON* is_optimized = cJSON_GetObjectItem(module, "isOptimized");
        cJSON* is_user_code = cJSON_GetObjectItem(module, "isUserCode");
        cJSON* version = cJSON_GetObjectItem(module, "version");
        cJSON* symbol_status = cJSON_GetObjectItem(module, "symbolStatus");
        cJSON* symbol_file_path = cJSON_GetObjectItem(module, "symbolFilePath");
        cJSON* date_time_stamp = cJSON_GetObjectItem(module, "dateTimeStamp");
        cJSON* address_range = cJSON_GetObjectItem(module, "addressRange");

        if (!id || !name || !path) {
            dap_modules_result_free(result);
            cJSON_Delete(root);
            return DAP_ERROR_PARSE_ERROR;
        }

        result->modules[i].id = strdup(id->valuestring);
        result->modules[i].name = strdup(name->valuestring);
        result->modules[i].path = strdup(path->valuestring);

        if (!result->modules[i].id || !result->modules[i].name || !result->modules[i].path) {
            dap_modules_result_free(result);
            cJSON_Delete(root);
            return DAP_ERROR_MEMORY;
        }

        if (is_optimized && cJSON_IsBool(is_optimized)) {
            result->modules[i].is_optimized = cJSON_IsTrue(is_optimized);
        }

        if (is_user_code && cJSON_IsBool(is_user_code)) {
            result->modules[i].is_user_code = cJSON_IsTrue(is_user_code);
        }

        if (version && cJSON_IsString(version)) {
            result->modules[i].version = strdup(version->valuestring);
            if (!result->modules[i].version) {
                dap_modules_result_free(result);
                cJSON_Delete(root);
                return DAP_ERROR_MEMORY;
            }
        }

        if (symbol_status && cJSON_IsString(symbol_status)) {
            result->modules[i].symbol_status = strdup(symbol_status->valuestring);
            if (!result->modules[i].symbol_status) {
                dap_modules_result_free(result);
                cJSON_Delete(root);
                return DAP_ERROR_MEMORY;
            }
        }

        if (symbol_file_path && cJSON_IsString(symbol_file_path)) {
            result->modules[i].symbol_file_path = strdup(symbol_file_path->valuestring);
            if (!result->modules[i].symbol_file_path) {
                dap_modules_result_free(result);
                cJSON_Delete(root);
                return DAP_ERROR_MEMORY;
            }
        }

        if (date_time_stamp && cJSON_IsString(date_time_stamp)) {
            result->modules[i].date_time_stamp = strdup(date_time_stamp->valuestring);
            if (!result->modules[i].date_time_stamp) {
                dap_modules_result_free(result);
                cJSON_Delete(root);
                return DAP_ERROR_MEMORY;
            }
        }

        if (address_range && cJSON_IsString(address_range)) {
            result->modules[i].address_range = strdup(address_range->valuestring);
            if (!result->modules[i].address_range) {
                dap_modules_result_free(result);
                cJSON_Delete(root);
                return DAP_ERROR_MEMORY;
            }
        }
    }

    cJSON_Delete(root);
    return DAP_ERROR_NONE;
}

/**
 * @brief Free a DAPSource structure and all its fields
 * 
 * @param source The source structure to free
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_source_free(DAPSource* source) {
    if (!source) {
        return DAP_ERROR_NONE;
    }

    // Free all string fields
    free(source->name);
    free(source->path);
    free(source->adapter_data);
    free(source->version);
    free(source->symbol_status);
    free(source->symbol_file_path);
    free(source->date_time_stamp);
    free(source->address_range);

    // Free sub-sources recursively
    if (source->sources) {
        for (size_t i = 0; i < source->num_sources; i++) {
            int error = dap_source_free(&source->sources[i]);
            if (error != DAP_ERROR_NONE) {
                return error;
            }
        }
        free(source->sources);
        source->sources = NULL;
        source->num_sources = 0;
    }

    // Free checksums
    if (source->checksums) {
        for (size_t i = 0; i < source->num_checksums; i++) {
            free(source->checksums[i].checksum);
        }
        free(source->checksums);
        source->checksums = NULL;
        source->num_checksums = 0;
    }

    return DAP_ERROR_NONE;
}

/**
 * @brief Free a DAPLoadSourcesResult structure
 * 
 * @param result The result structure to free
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_load_sources_result_free(DAPLoadSourcesResult* result) {
    if (!result) {
        return DAP_ERROR_NONE;
    }

    if (result->sources) {
        for (size_t i = 0; i < result->num_sources; i++) {
            int error = dap_source_free(&result->sources[i]);
            if (error != DAP_ERROR_NONE) {
                return error;
            }
        }
        free(result->sources);
        result->sources = NULL;
        result->num_sources = 0;
    }

    return DAP_ERROR_NONE;
}

int dap_client_load_sources(DAPClient* client, DAPLoadSourcesResult* result) {
    if (!client || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_LOADED_SOURCES, NULL, &response);
    if (error != DAP_ERROR_NONE) {
        return error;
    }

    if (!response) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* root = cJSON_Parse(response);
    free(response);

    if (!root) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* body = cJSON_GetObjectItem(root, "body");
    if (!body) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* sources = cJSON_GetObjectItem(body, "sources");
    if (!sources || !cJSON_IsArray(sources)) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    int source_count = cJSON_GetArraySize(sources);
    result->sources = calloc(source_count, sizeof(DAPSource));
    if (!result->sources) {
        cJSON_Delete(root);
        return DAP_ERROR_MEMORY;
    }

    result->num_sources = source_count;

    for (int i = 0; i < source_count; i++) {
        cJSON* source = cJSON_GetArrayItem(sources, i);
        if (!source) {
            dap_load_sources_result_free(result);
            cJSON_Delete(root);
            return DAP_ERROR_PARSE_ERROR;
        }

        DAPSource* parsed = dap_source_parse(source);
        if (!parsed) {
            dap_load_sources_result_free(result);
            cJSON_Delete(root);
            return DAP_ERROR_MEMORY;
        }

        result->sources[i] = *parsed;
        free(parsed);
    }

    cJSON_Delete(root);
    return DAP_ERROR_NONE;
}

/**
 * @brief Read memory from the debuggee
 * 
 * @param client Pointer to the client
 * @param memory_reference Memory reference to read from
 * @param offset Offset from the memory reference
 * @param count Number of bytes to read
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_read_memory(DAPClient* client, const char* memory_reference, uint64_t offset, size_t count, DAPReadMemoryResult* result) {
    if (!client || !memory_reference || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    cJSON_AddStringToObject(args, "memoryReference", memory_reference);
    cJSON_AddNumberToObject(args, "offset", offset);
    cJSON_AddNumberToObject(args, "count", count);

    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_READ_MEMORY, args, &response);
    cJSON_Delete(args);

    if (error != DAP_ERROR_NONE) {
        return error;
    }

    if (!response) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* root = cJSON_Parse(response);
    free(response);

    if (!root) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* body = cJSON_GetObjectItem(root, "body");
    if (!body) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* address = cJSON_GetObjectItem(body, "address");
    cJSON* unreadable_bytes = cJSON_GetObjectItem(body, "unreadableBytes");
    cJSON* data = cJSON_GetObjectItem(body, "data");

    if (!address || !data) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    result->address = strdup(address->valuestring);
    result->unreadable_bytes = unreadable_bytes ? unreadable_bytes->valueint : 0;
    result->data = strdup(data->valuestring);

    if (!result->address || !result->data) {
        free(result->address);
        free(result->data);
        cJSON_Delete(root);
        return DAP_ERROR_MEMORY;
    }

    cJSON_Delete(root);
    return DAP_ERROR_NONE;
}

/**
 * @brief Write memory to the debuggee
 * 
 * @param client Pointer to the client
 * @param memory_reference Memory reference to write to
 * @param offset Offset from the memory reference
 * @param data Data to write
 * @param allow_partial Whether to allow partial writes
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_write_memory(DAPClient* client, const char* memory_reference, uint64_t offset, const char* data, bool allow_partial, DAPWriteMemoryResult* result) {
    if (!client || !memory_reference || !data || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    cJSON_AddStringToObject(args, "memoryReference", memory_reference);
    cJSON_AddNumberToObject(args, "offset", offset);
    cJSON_AddStringToObject(args, "data", data);
    cJSON_AddBoolToObject(args, "allowPartial", allow_partial);

    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_WRITE_MEMORY, args, &response);
    cJSON_Delete(args);

    if (error != DAP_ERROR_NONE) {
        return error;
    }

    if (!response) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* root = cJSON_Parse(response);
    free(response);

    if (!root) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* body = cJSON_GetObjectItem(root, "body");
    if (!body) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* bytes_written = cJSON_GetObjectItem(body, "bytesWritten");
    cJSON* offset_result = cJSON_GetObjectItem(body, "offset");

    if (!bytes_written) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    result->bytes_written = bytes_written->valueint;
    result->offset = offset_result ? (uint64_t)offset_result->valueint : offset;

    cJSON_Delete(root);
    return DAP_ERROR_NONE;
}

/**
 * @brief Disassemble memory
 * 
 * @param client Pointer to the client
 * @param memory_reference Memory reference to disassemble
 * @param offset Offset from the memory reference
 * @param instruction_offset Instruction offset
 * @param instruction_count Number of instructions to disassemble
 * @param resolve_symbols Whether to resolve symbols
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_disassemble(DAPClient* client, const char* memory_reference, uint64_t offset, size_t instruction_offset, size_t instruction_count, bool resolve_symbols, DAPDisassembleResult* result) {
    if (!client || !memory_reference || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    cJSON_AddStringToObject(args, "memoryReference", memory_reference);
    cJSON_AddNumberToObject(args, "offset", offset);
    cJSON_AddNumberToObject(args, "instructionOffset", instruction_offset);
    cJSON_AddNumberToObject(args, "instructionCount", instruction_count);
    cJSON_AddBoolToObject(args, "resolveSymbols", resolve_symbols);

    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_DISASSEMBLE, args, &response);
    cJSON_Delete(args);

    if (error != DAP_ERROR_NONE) {
        return error;
    }

    if (!response) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* root = cJSON_Parse(response);
    free(response);

    if (!root) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* body = cJSON_GetObjectItem(root, "body");
    if (!body) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* instructions_json = cJSON_GetObjectItem(body, "instructions");
    if (!instructions_json || !cJSON_IsArray(instructions_json)) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    result->num_instructions = cJSON_GetArraySize(instructions_json);
    result->instructions = malloc(result->num_instructions * sizeof(DAPDisassembledInstruction));
    if (!result->instructions) {
        cJSON_Delete(root);
        return DAP_ERROR_MEMORY;
    }

    memset(result->instructions, 0, result->num_instructions * sizeof(DAPDisassembledInstruction));

    size_t i;
    for (i = 0; i < result->num_instructions; i++) {
        cJSON* instruction = cJSON_GetArrayItem(instructions_json, i);
        if (!instruction) {
            for (size_t j = 0; j < i; j++) {
                free(result->instructions[j].address);
                free(result->instructions[j].instruction_bytes);
                free(result->instructions[j].instruction);
                free(result->instructions[j].symbol);
                if (result->instructions[j].location) {
                    dap_source_free(result->instructions[j].location);
                }
            }
            free(result->instructions);
            cJSON_Delete(root);
            return DAP_ERROR_PARSE_ERROR;
        }

        cJSON* address = cJSON_GetObjectItem(instruction, "address");
        cJSON* instruction_bytes = cJSON_GetObjectItem(instruction, "instructionBytes");
        cJSON* instruction_text = cJSON_GetObjectItem(instruction, "instruction");
        cJSON* symbol = cJSON_GetObjectItem(instruction, "symbol");
        cJSON* location = cJSON_GetObjectItem(instruction, "location");
        cJSON* line = cJSON_GetObjectItem(instruction, "line");
        cJSON* column = cJSON_GetObjectItem(instruction, "column");
        cJSON* end_line = cJSON_GetObjectItem(instruction, "endLine");
        cJSON* end_column = cJSON_GetObjectItem(instruction, "endColumn");

        if (address) {
            result->instructions[i].address = strdup(address->valuestring);
            if (!result->instructions[i].address) {
                goto cleanup_error;
            }
        }
        if (instruction_bytes) {
            result->instructions[i].instruction_bytes = strdup(instruction_bytes->valuestring);
            if (!result->instructions[i].instruction_bytes) {
                goto cleanup_error;
            }
        }
        if (instruction_text) {
            result->instructions[i].instruction = strdup(instruction_text->valuestring);
            if (!result->instructions[i].instruction) {
                goto cleanup_error;
            }
        }
        if (symbol) {
            result->instructions[i].symbol = strdup(symbol->valuestring);
            if (!result->instructions[i].symbol) {
                goto cleanup_error;
            }
        }
        if (location) {
            result->instructions[i].location = dap_source_parse(location);
            if (!result->instructions[i].location) {
                goto cleanup_error;
            }
        }
        if (line) {
            result->instructions[i].line = line->valueint;
        }
        if (column) {
            result->instructions[i].column = column->valueint;
        }
        if (end_line) {
            result->instructions[i].end_line = end_line->valueint;
        }
        if (end_column) {
            result->instructions[i].end_column = end_column->valueint;
        }
    }

    cJSON_Delete(root);
    return DAP_ERROR_NONE;

cleanup_error:
    for (size_t j = 0; j < i; j++) {
        free(result->instructions[j].address);
        free(result->instructions[j].instruction_bytes);
        free(result->instructions[j].instruction);
        free(result->instructions[j].symbol);
        if (result->instructions[j].location) {
            dap_source_free(result->instructions[j].location);
        }
    }
    free(result->instructions);
    cJSON_Delete(root);
    return DAP_ERROR_MEMORY;
}

/**
 * @brief Step (generic step function)
 * 
 * @param client Pointer to the client
 * @param thread_id Thread ID to step
 * @param single_thread Whether to continue only the specified thread
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_step(DAPClient* client, int thread_id, bool single_thread, DAPStepResult* result) {
    // This is a convenience wrapper around dap_client_next
    return dap_client_next(client, thread_id, NULL, single_thread, result);
}

/**
 * @brief Step over (next) in the current thread
 * 
 * @param client Pointer to the client
 * @param thread_id Thread ID to step
 * @param granularity Step granularity (optional)
 * @param single_thread Whether to continue only the specified thread
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_next(DAPClient* client, int thread_id, const char* granularity, 
                   bool single_thread, DAPStepResult* result) {
    if (!client || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    // Create request arguments
    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    // Add required threadId
    cJSON_AddNumberToObject(args, "threadId", thread_id);
    
    // Add optional arguments if provided
    if (granularity) {
        cJSON_AddStringToObject(args, "granularity", granularity);
    }
    
    // Add single thread flag if needed
    if (single_thread) {
        cJSON_AddBoolToObject(args, "singleThread", single_thread);
    }

    // Send request
    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_NEXT, args, &response);
    cJSON_Delete(args);

    if (error != DAP_ERROR_NONE) {
        return error;
    }

    // Parse response
    cJSON* json = cJSON_Parse(response);
    if (!json) {
        free(response);
        return DAP_ERROR_PARSE_ERROR;
    }

    // Check for success
    cJSON* success = cJSON_GetObjectItem(json, "success");
    if (!success || !cJSON_IsBool(success) || !success->valueint) {
        cJSON_Delete(json);
        free(response);
        return DAP_ERROR_REQUEST_FAILED;
    }

    // Parse response body
    cJSON* body = cJSON_GetObjectItem(json, "body");
    if (body) {
        cJSON* all_threads_stopped = cJSON_GetObjectItem(body, "allThreadsStopped");
        if (all_threads_stopped && cJSON_IsBool(all_threads_stopped)) {
            result->all_threads_stopped = cJSON_IsTrue(all_threads_stopped);
        }
    }

    result->base.success = true;
    result->base.message = NULL;

    cJSON_Delete(json);
    free(response);
    return DAP_ERROR_NONE;
}

int dap_client_get_threads(DAPClient* client, DAPThread** threads, int* count) {
    if (!client || !threads || !count) return DAP_ERROR_INVALID_ARG;
    *threads = NULL;
    *count = 0;

    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_THREADS, NULL, &response);
    if (error != DAP_ERROR_NONE) return error;
    if (!response) return DAP_ERROR_PARSE_ERROR;

    cJSON* root = cJSON_Parse(response);
    free(response);
    if (!root) return DAP_ERROR_PARSE_ERROR;

    cJSON* body = cJSON_GetObjectItem(root, "body");
    if (!body) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* threads_json = cJSON_GetObjectItem(body, "threads");
    if (!threads_json || !cJSON_IsArray(threads_json)) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    int num_threads = cJSON_GetArraySize(threads_json);
    if (num_threads == 0) {
        cJSON_Delete(root);
        return DAP_ERROR_NONE; // Empty thread list is valid
    }

    *threads = malloc(num_threads * sizeof(DAPThread));
    if (!*threads) {
        cJSON_Delete(root);
        return DAP_ERROR_MEMORY;
    }

    for (int i = 0; i < num_threads; i++) {
        cJSON* thread_json = cJSON_GetArrayItem(threads_json, i);
        if (!thread_json) {
            // Clean up allocated memory
            for (int j = 0; j < i; j++) {
                free((*threads)[j].name);
            }
            free(*threads);
            *threads = NULL;
            cJSON_Delete(root);
            return DAP_ERROR_PARSE_ERROR;
        }

        cJSON* id = cJSON_GetObjectItem(thread_json, "id");
        cJSON* name = cJSON_GetObjectItem(thread_json, "name");
        cJSON* state = cJSON_GetObjectItem(thread_json, "state");

        (*threads)[i].id = id ? id->valueint : (i+1);
        (*threads)[i].name = name && cJSON_IsString(name) ? strdup(name->valuestring) : strdup("thread");
        
        // Parse thread state
        if (state && cJSON_IsString(state)) {
            if (strcmp(state->valuestring, "running") == 0) {
                (*threads)[i].state = DAP_THREAD_STATE_RUNNING;
            } else if (strcmp(state->valuestring, "stopped") == 0 || strcmp(state->valuestring, "paused") == 0) {
                (*threads)[i].state = DAP_THREAD_STATE_STOPPED;
            } else if (strcmp(state->valuestring, "terminated") == 0) {
                (*threads)[i].state = DAP_THREAD_STATE_TERMINATED;
            } else {
                // Only warn for truly unknown states
                fprintf(stderr, "Warning: Unknown thread state '%s', defaulting to STOPPED\n", state->valuestring);
                (*threads)[i].state = DAP_THREAD_STATE_STOPPED;
            }
        } else {
            // Missing state - use STOPPED as per DAP spec
            (*threads)[i].state = DAP_THREAD_STATE_STOPPED;
            fprintf(stderr, "Warning: Missing thread state, defaulting to STOPPED\n");
        }
    }

    *count = num_threads;
    cJSON_Delete(root);
    return DAP_ERROR_NONE;
}

int dap_client_pause(DAPClient* client, int thread_id, DAPPauseResult* result) {
    if (!client || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    // Create request arguments
    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    // Add required threadId
    cJSON_AddNumberToObject(args, "threadId", thread_id);

    // Send request
    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_PAUSE, args, &response);
    cJSON_Delete(args);

    if (error != DAP_ERROR_NONE) {
        return error;
    }

    // Parse response
    cJSON* json = cJSON_Parse(response);
    if (!json) {
        free(response);
        return DAP_ERROR_PARSE_ERROR;
    }

    // Check for success
    cJSON* success = cJSON_GetObjectItem(json, "success");
    if (!success || !cJSON_IsBool(success) || !success->valueint) {
        cJSON_Delete(json);
        free(response);
        return DAP_ERROR_REQUEST_FAILED;
    }

    // Parse response body
    cJSON* body = cJSON_GetObjectItem(json, "body");
    if (body) {
        cJSON* all_threads_stopped = cJSON_GetObjectItem(body, "allThreadsStopped");
        if (all_threads_stopped && cJSON_IsBool(all_threads_stopped)) {
            result->all_threads_stopped = cJSON_IsTrue(all_threads_stopped);
        }
    }

    result->base.success = true;
    result->base.message = NULL;
    result->thread_id = thread_id;
    result->reason = "pause";  // According to DAP spec, reason is "pause"

    cJSON_Delete(json);
    free(response);
    return DAP_ERROR_NONE;
}

int dap_client_continue(DAPClient* client, int thread_id, bool single_thread, DAPContinueResult* result) {
    if (!client || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    // Create request arguments
    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    // Add required threadId
    cJSON_AddNumberToObject(args, "threadId", thread_id);
    
    // Add single thread flag if needed
    if (single_thread) {
        cJSON_AddBoolToObject(args, "singleThread", single_thread);
    }

    // Send request
    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_CONTINUE, args, &response);
    cJSON_Delete(args);

    if (error != DAP_ERROR_NONE) {
        return error;
    }

    // Parse response
    cJSON* json = cJSON_Parse(response);
    if (!json) {
        free(response);
        return DAP_ERROR_PARSE_ERROR;
    }

    // Check for success
    cJSON* success = cJSON_GetObjectItem(json, "success");
    if (!success || !cJSON_IsBool(success) || !success->valueint) {
        cJSON_Delete(json);
        free(response);
        return DAP_ERROR_REQUEST_FAILED;
    }

    // Parse response body
    cJSON* body = cJSON_GetObjectItem(json, "body");
    if (body) {
        cJSON* all_threads_continued = cJSON_GetObjectItem(body, "allThreadsContinued");
        if (all_threads_continued && cJSON_IsBool(all_threads_continued)) {
            result->all_threads_continued = cJSON_IsTrue(all_threads_continued);
        }
    }

    result->base.success = true;
    result->base.message = NULL;

    cJSON_Delete(json);
    free(response);
    return DAP_ERROR_NONE;
}

int dap_client_get_stack_trace(DAPClient* client, int thread_id, DAPStackFrame** frames, int* frame_count) {
    (void)client; (void)thread_id; (void)frames; (void)frame_count;
    return DAP_ERROR_NOT_IMPLEMENTED;
}

int dap_client_initialize(DAPClient* client) {
    if (!client) return DAP_ERROR_INVALID_ARG;
    
    // Create initialize arguments
    cJSON* args = cJSON_CreateObject();
    if (!args) return DAP_ERROR_MEMORY;
    
    // Required fields
    cJSON_AddStringToObject(args, "clientID", "nd100x-debugger");
    cJSON_AddStringToObject(args, "clientName", "ND100X Debugger");
    cJSON_AddStringToObject(args, "adapterID", "nd100x");
    cJSON_AddStringToObject(args, "pathFormat", "path");
    cJSON_AddBoolToObject(args, "linesStartAt1", true);
    cJSON_AddBoolToObject(args, "columnsStartAt1", true);
    
    // Client capabilities
    cJSON* capabilities = cJSON_CreateObject();
    if (!capabilities) {
        cJSON_Delete(args);
        return DAP_ERROR_MEMORY;
    }
    
    // Core capabilities
    cJSON_AddBoolToObject(capabilities, "supportsConfigurationDoneRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsFunctionBreakpoints", true);
    cJSON_AddBoolToObject(capabilities, "supportsConditionalBreakpoints", true);
    cJSON_AddBoolToObject(capabilities, "supportsHitConditionalBreakpoints", true);
    cJSON_AddBoolToObject(capabilities, "supportsEvaluateForHovers", true);
    cJSON_AddBoolToObject(capabilities, "supportsSetVariable", true);
    cJSON_AddBoolToObject(capabilities, "supportsRestartFrame", true);
    cJSON_AddBoolToObject(capabilities, "supportsGotoTargetsRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsStepInTargetsRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsCompletionsRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsModulesRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsRestartRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsExceptionOptions", true);
    cJSON_AddBoolToObject(capabilities, "supportsValueFormattingOptions", true);
    cJSON_AddBoolToObject(capabilities, "supportsExceptionInfoRequest", true);
    cJSON_AddBoolToObject(capabilities, "supportsTerminateDebuggee", true);
    cJSON_AddBoolToObject(capabilities, "supportsSuspendDebuggee", true);
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
    cJSON_AddBoolToObject(capabilities, "supportsExceptionFilters", true);
    cJSON_AddBoolToObject(capabilities, "supportsSingleThreadExecutionRequests", true);
    
    // Add capabilities to args
    cJSON_AddItemToObject(args, "capabilities", capabilities);
    
    // Send initialize request
    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_INITIALIZE, args, &response);
    cJSON_Delete(args);
    
    if (error != DAP_ERROR_NONE) {
        if (response) free(response);
        return error;
    }
    
    // Parse response
    if (response) {
        cJSON* json = cJSON_Parse(response);
        if (json) {
            cJSON* success = cJSON_GetObjectItem(json, "success");
            if (success && cJSON_IsBool(success) && !success->valueint) {
                cJSON* message = cJSON_GetObjectItem(json, "message");
                if (message && cJSON_IsString(message)) {
                    DAP_CLIENT_DEBUG_LOG("Initialize failed: %s", message->valuestring);
                }
                cJSON_Delete(json);
                free(response);
                return DAP_ERROR_REQUEST_FAILED;
            }
            
            // Store server capabilities if needed
            cJSON* body = cJSON_GetObjectItem(json, "body");
            if (body) {
                cJSON* server_capabilities = cJSON_GetObjectItem(body, "capabilities");
                if (server_capabilities) {
                    // TODO: Store server capabilities for later use
                }
            }
            
            cJSON_Delete(json);
        }
        free(response);
    }
    
    return DAP_ERROR_NONE;
}

int dap_client_launch(DAPClient* client, const char* program_path, bool stop_at_entry) {
    if (!client || !program_path) return DAP_ERROR_INVALID_ARG;
    cJSON* args = cJSON_CreateObject();
    if (!args) return DAP_ERROR_MEMORY;
    cJSON_AddStringToObject(args, "program", program_path);
    cJSON_AddBoolToObject(args, "stopOnEntry", stop_at_entry);
    cJSON_AddBoolToObject(args, "noDebug", false);

    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_LAUNCH, args, &response);
    cJSON_Delete(args);
    if (error != DAP_ERROR_NONE) return error;
    if (response) free(response);
    return DAP_ERROR_NONE;
}

/**
 * @brief Receive a message from the DAP server
 * 
 * @param client Pointer to the client
 * @param message Output parameter for the received message
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_receive_message(DAPClient* client, cJSON** message) {
    if (!client || !message) {
        return DAP_ERROR_INVALID_ARG;
    }

    // Receive message using transport layer
    char* response = NULL;
    int result = dap_transport_receive(client->transport, &response);
    if (result != 0) {
        if (result == -1) {
            return DAP_ERROR_TRANSPORT;
        }
        return result;
    }

    // Log the received message if debug mode is enabled
    if (client->debug_mode && response) {
        dap_debug_log_message(client, "Receive", response);
    }

    // Parse JSON
    *message = cJSON_Parse(response);
    free(response);

    if (!*message) {
        return DAP_ERROR_PARSE_ERROR;
    }

    return DAP_ERROR_NONE;
}

// DAP step command stubs for linker resolution
int dap_client_step_in(DAPClient* client, int thread_id, const char* target_id, const char* granularity, DAPStepInResult* result) {
    if (!client || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    // Create request arguments
    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    // Add required threadId
    cJSON_AddNumberToObject(args, "threadId", thread_id);

    // Add optional arguments if provided
    if (target_id) {
        cJSON_AddNumberToObject(args, "targetId", atoi(target_id));
    }

    if (granularity) {
        cJSON_AddStringToObject(args, "granularity", granularity);
    }

    // Send request
    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_STEP_IN, args, &response);
    cJSON_Delete(args);

    if (error != DAP_ERROR_NONE) {
        return error;
    }

    // Parse response
    cJSON* json = cJSON_Parse(response);
    if (!json) {
        free(response);
        return DAP_ERROR_PARSE_ERROR;
    }

    // Check for success
    cJSON* success = cJSON_GetObjectItem(json, "success");
    if (!success || !cJSON_IsBool(success) || !success->valueint) {
        cJSON_Delete(json);
        free(response);
        return DAP_ERROR_REQUEST_FAILED;
    }

    // Parse response body
    cJSON* body = cJSON_GetObjectItem(json, "body");
    if (body) {
        cJSON* all_threads_stopped = cJSON_GetObjectItem(body, "allThreadsStopped");
        if (all_threads_stopped && cJSON_IsBool(all_threads_stopped)) {
            result->all_threads_stopped = cJSON_IsTrue(all_threads_stopped);
        }
    }

    result->base.success = true;
    result->base.message = NULL;

    cJSON_Delete(json);
    free(response);
    return DAP_ERROR_NONE;
}

int dap_client_step_out(DAPClient* client, int thread_id, DAPStepOutResult* result) {
    (void)client; (void)thread_id; (void)result;
    return -1; // Not implemented
}

int dap_client_step_back(DAPClient* client, int thread_id, DAPStepBackResult* result) {
    (void)client; (void)thread_id; (void)result;
    return -1; // Not implemented
}

/**
 * @brief Get scopes for a stack frame
 * 
 * @param client Pointer to the client
 * @param frame_id Frame ID
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_get_scopes(DAPClient* client, int frame_id, DAPGetScopesResult* result) {
    if (!client || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    cJSON_AddNumberToObject(args, "frameId", frame_id);

    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_SCOPES, args, &response);
    cJSON_Delete(args);

    if (error != DAP_ERROR_NONE) {
        return error;
    }

    if (!response) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* root = cJSON_Parse(response);
    free(response);

    if (!root) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* body = cJSON_GetObjectItem(root, "body");
    if (!body) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* scopes = cJSON_GetObjectItem(body, "scopes");
    if (!scopes || !cJSON_IsArray(scopes)) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }

    int num_scopes = cJSON_GetArraySize(scopes);
    result->scopes = calloc(num_scopes, sizeof(DAPScope));
    if (!result->scopes) {
        cJSON_Delete(root);
        return DAP_ERROR_MEMORY;
    }

    result->num_scopes = num_scopes;

    for (int i = 0; i < num_scopes; i++) {
        cJSON* scope = cJSON_GetArrayItem(scopes, i);
        if (!scope) {
            dap_get_scopes_result_free(result);
            cJSON_Delete(root);
            return DAP_ERROR_PARSE_ERROR;
        }

        cJSON* name = cJSON_GetObjectItem(scope, "name");
        cJSON* variables_reference = cJSON_GetObjectItem(scope, "variablesReference");
        cJSON* named_variables = cJSON_GetObjectItem(scope, "namedVariables");
        cJSON* indexed_variables = cJSON_GetObjectItem(scope, "indexedVariables");
        cJSON* expensive = cJSON_GetObjectItem(scope, "expensive");
        cJSON* source = cJSON_GetObjectItem(scope, "source");
        cJSON* line = cJSON_GetObjectItem(scope, "line");
        cJSON* column = cJSON_GetObjectItem(scope, "column");
        cJSON* end_line = cJSON_GetObjectItem(scope, "endLine");
        cJSON* end_column = cJSON_GetObjectItem(scope, "endColumn");

        if (!name || !variables_reference) {
            dap_get_scopes_result_free(result);
            cJSON_Delete(root);
            return DAP_ERROR_PARSE_ERROR;
        }

        result->scopes[i].name = strdup(name->valuestring);
        result->scopes[i].variables_reference = variables_reference->valueint;
        result->scopes[i].named_variables = named_variables ? named_variables->valueint : 0;
        result->scopes[i].indexed_variables = indexed_variables ? indexed_variables->valueint : 0;
        result->scopes[i].expensive = expensive ? cJSON_IsTrue(expensive) : false;

        if (source) {
            DAPSource* parsed = dap_source_parse(source);
            if (parsed) {
                result->scopes[i].source_path = parsed->path;
                free(parsed);
            }
        }

        result->scopes[i].line = line ? line->valueint : 0;
        result->scopes[i].column = column ? column->valueint : 0;
        result->scopes[i].end_line = end_line ? end_line->valueint : 0;
        result->scopes[i].end_column = end_column ? end_column->valueint : 0;

        if (!result->scopes[i].name) {
            dap_get_scopes_result_free(result);
            cJSON_Delete(root);
            return DAP_ERROR_MEMORY;
        }
    }

    cJSON_Delete(root);
    return DAP_ERROR_NONE;
}

/**
 * @brief Free memory allocated for a scopes result
 * 
 * @param result Result to free
 */
void dap_get_scopes_result_free(DAPGetScopesResult* result) {
    if (!result) {
        return;
    }

    if (result->scopes) {
        for (size_t i = 0; i < result->num_scopes; i++) {
            if (result->scopes[i].name) {
                free(result->scopes[i].name);
            }
            if (result->scopes[i].source_path) {
                free(result->scopes[i].source_path);
            }
        }
        free(result->scopes);
    }
}

// Forward declaration
static int dap_parse_variables_response(cJSON* response, DAPGetVariablesResult* result);

int dap_client_get_variables(DAPClient* client, int variables_reference, int start, int count, DAPGetVariablesResult* result) {
    if (!client || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    // Create request arguments
    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    cJSON_AddNumberToObject(args, "variablesReference", variables_reference);
    if (start > 0) {
        cJSON_AddNumberToObject(args, "start", start);
    }
    if (count > 0) {
        cJSON_AddNumberToObject(args, "count", count);
    }

    // Send request and get response
    char* response_body = NULL;
    int error = dap_client_send_request(client, DAP_CMD_VARIABLES, args, &response_body);
    cJSON_Delete(args);

    if (error != DAP_ERROR_NONE) {
        return error;
    }

    if (!response_body) {
        return DAP_ERROR_INVALID_RESPONSE;
    }

    // Parse response
    cJSON* response = cJSON_Parse(response_body);
    free(response_body);

    if (!response) {
        return DAP_ERROR_INVALID_RESPONSE;
    }

    error = dap_parse_variables_response(response, result);
    cJSON_Delete(response);

    return error;
}

void dap_get_variables_result_free(DAPGetVariablesResult* result) {
    if (!result) return;

    if (result->variables) {
        for (size_t i = 0; i < result->num_variables; i++) {
            DAPVariable* var = &result->variables[i];
            free(var->name);
            free(var->value);
            free(var->type);
            free(var->memory_reference);
            // presentation_hint is an enum, not a string
            var->presentation_hint = DAP_VARIABLE_PRESENTATION_NORMAL;
        }
        free(result->variables);
        result->variables = NULL;
        result->num_variables = 0;
    }
}

static int dap_parse_variables_response(cJSON* response, DAPGetVariablesResult* result) {
    if (!response || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    // Check for error response first
    cJSON* success = cJSON_GetObjectItem(response, "success");
    if (success && !cJSON_IsTrue(success)) {
        cJSON* body = cJSON_GetObjectItem(response, "body");
        if (body) {
            cJSON* error = cJSON_GetObjectItem(body, "error");
            if (error) {
                cJSON* id = cJSON_GetObjectItem(error, "id");
                cJSON* format = cJSON_GetObjectItem(error, "format");
                cJSON* variables_reference = cJSON_GetObjectItem(error, "variablesReference");
                if (id && format && variables_reference) {
                    // Format the error message
                    char error_msg[256];
                    snprintf(error_msg, sizeof(error_msg), format->valuestring, variables_reference->valueint);
                    fprintf(stderr, "Error: %s\n", error_msg);
                    return id->valueint;
                }
            }
        }
        return DAP_ERROR_REQUEST_FAILED;
    }

    // Get body object first
    cJSON* body = cJSON_GetObjectItem(response, "body");
    if (!body || !cJSON_IsObject(body)) {
        return DAP_ERROR_INVALID_RESPONSE;
    }

    // Get variables array from body
    cJSON* variables_array = cJSON_GetObjectItem(body, "variables");
    if (!variables_array || !cJSON_IsArray(variables_array)) {
        return DAP_ERROR_INVALID_RESPONSE;
    }

    // Allocate memory for variables
    result->num_variables = cJSON_GetArraySize(variables_array);
    result->variables = calloc(result->num_variables, sizeof(DAPVariable));
    if (!result->variables) {
        return DAP_ERROR_MEMORY;
    }

    // Parse each variable
    int i = 0;
    cJSON* variable_item = NULL;
    cJSON_ArrayForEach(variable_item, variables_array) {
        DAPVariable* var = &result->variables[i];
        
        // Required fields according to DAP spec
        cJSON* name = cJSON_GetObjectItem(variable_item, "name");
        cJSON* value = cJSON_GetObjectItem(variable_item, "value");
        cJSON* variables_reference = cJSON_GetObjectItem(variable_item, "variablesReference");
        
        if (!name || !value || !variables_reference) {
            return DAP_ERROR_INVALID_RESPONSE;
        }

        var->name = strdup(name->valuestring);
        var->value = strdup(value->valuestring);
        var->variables_reference = variables_reference->valueint;

        // Optional fields according to DAP spec
        cJSON* type = cJSON_GetObjectItem(variable_item, "type");
        if (type) {
            var->type = strdup(type->valuestring);
        }

        cJSON* named_variables = cJSON_GetObjectItem(variable_item, "namedVariables");
        if (named_variables) {
            var->named_variables = named_variables->valueint;
        }

        cJSON* indexed_variables = cJSON_GetObjectItem(variable_item, "indexedVariables");
        if (indexed_variables) {
            var->indexed_variables = indexed_variables->valueint;
        }

        cJSON* memory_reference = cJSON_GetObjectItem(variable_item, "memoryReference");
        if (memory_reference) {
            var->memory_reference = strdup(memory_reference->valuestring);
        }

        cJSON* presentation_hint = cJSON_GetObjectItem(variable_item, "presentationHint");
        if (presentation_hint) {
            // Parse presentation hint according to DAP spec
            cJSON* kind = cJSON_GetObjectItem(presentation_hint, "kind");
            if (kind) {
                if (strcmp(kind->valuestring, "readOnly") == 0) {
                    var->presentation_hint = DAP_VARIABLE_PRESENTATION_READONLY;
                } else if (strcmp(kind->valuestring, "hidden") == 0) {
                    var->presentation_hint = DAP_VARIABLE_PRESENTATION_HIDDEN;
                } else {
                    var->presentation_hint = DAP_VARIABLE_PRESENTATION_NORMAL;
                }
            }
        }

        i++;
    }

    return DAP_ERROR_NONE;
}

/**
 * @brief Evaluate an expression in the debug target
 * 
 * @param client Pointer to the client
 * @param expression Expression to evaluate
 * @param frame_id Frame ID for context or 0 for global context
 * @param context Context hint (e.g., "watch", "repl", "hover")
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_evaluate(DAPClient* client, const char* expression, int frame_id, const char* context, DAPEvaluateResult* result) {
    if (!client || !expression || !result) {
        return DAP_ERROR_INVALID_ARG;
    }
    
    // Initialize result structure
    memset(result, 0, sizeof(DAPEvaluateResult));
    result->base.success = false;
    
    // Create arguments JSON object
    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }
    
    // Add required/optional arguments
    cJSON_AddStringToObject(args, "expression", expression);
    if (frame_id > 0) {
        cJSON_AddNumberToObject(args, "frameId", frame_id);
    }
    if (context && *context) {
        cJSON_AddStringToObject(args, "context", context);
    }
    
    // Send evaluate request to the server
    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_EVALUATE, args, &response);
    
    // Clean up arguments
    cJSON_Delete(args);
    
    if (error != DAP_ERROR_NONE) {
        return error;
    }
    
    if (!response) {
        return DAP_ERROR_PARSE_ERROR;
    }
    
    // Parse response
    cJSON* root = cJSON_Parse(response);
    free(response);  // Free the response string now that we've parsed it
    
    if (!root) {
        return DAP_ERROR_PARSE_ERROR;
    }
    
    // Get response body
    cJSON* body = cJSON_GetObjectItem(root, "body");
    if (!body) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }
    
    // Extract evaluation result
    cJSON* result_json = cJSON_GetObjectItem(body, "result");
    if (!result_json || !cJSON_IsString(result_json)) {
        cJSON_Delete(root);
        return DAP_ERROR_PARSE_ERROR;
    }
    
    // Set success flag
    result->base.success = true;
    
    // Copy result string
    result->result = strdup(result_json->valuestring);
    if (!result->result) {
        cJSON_Delete(root);
        return DAP_ERROR_MEMORY;
    }
    
    // Extract optional type
    cJSON* type = cJSON_GetObjectItem(body, "type");
    if (type && cJSON_IsString(type)) {
        result->type = strdup(type->valuestring);
        // Non-fatal if type allocation fails
    }
    
    // Extract optional variables reference
    cJSON* variables_reference = cJSON_GetObjectItem(body, "variablesReference");
    if (variables_reference && cJSON_IsNumber(variables_reference)) {
        result->variables_reference = variables_reference->valueint;
    } else {
        result->variables_reference = 0;
    }
    
    cJSON_Delete(root);
    return DAP_ERROR_NONE;
}

/**
 * @brief Clean up an evaluate result structure
 * 
 * @param result Pointer to the result structure to clean up
 */
void dap_evaluate_result_free(DAPEvaluateResult* result) {
    if (!result) {
        return;
    }
    
    free(result->result);
    free(result->type);
    
    // Reset the structure
    memset(result, 0, sizeof(DAPEvaluateResult));
}

/**
 * @brief Free memory allocated for a disassemble result
 * 
 * @param result Result to free
 */
void dap_disassemble_result_free(DAPDisassembleResult* result) {
    if (!result) {
        return;
    }

    if (result->instructions) {
        for (size_t i = 0; i < result->num_instructions; i++) {
            free(result->instructions[i].address);
            free(result->instructions[i].instruction_bytes);
            free(result->instructions[i].instruction);
            free(result->instructions[i].symbol);
            if (result->instructions[i].location) {
                dap_source_free(result->instructions[i].location);
            }
        }
        free(result->instructions);
    }

    result->instructions = NULL;
    result->num_instructions = 0;
}

/**
 * @brief Get breakpoints for a source file
 * 
 * @param client Pointer to the client
 * @param source_path Source file path
 * @param count Output number of breakpoints found
 * @return DAPBreakpoint* Array of breakpoints (must be freed by caller), NULL on error
 */
DAPBreakpoint* dap_client_get_breakpoints_by_source(DAPClient* client, const char* source_path, int* count) {
    if (!client || !source_path || !count) {
        return NULL;
    }
    
    // Count breakpoints matching this source path
    *count = 0;
    for (int i = 0; i < client->num_breakpoints; i++) {
        if (client->breakpoints[i].source && 
            client->breakpoints[i].source->path &&
            strcmp(client->breakpoints[i].source->path, source_path) == 0) {
            (*count)++;
        }
    }
    
    if (*count == 0) {
        return NULL;
    }
    
    // Allocate memory for results
    DAPBreakpoint* breakpoints = malloc(sizeof(DAPBreakpoint) * (*count));
    if (!breakpoints) {
        *count = 0;
        return NULL;
    }
    
    // Copy breakpoints
    int index = 0;
    for (int i = 0; i < client->num_breakpoints; i++) {
        if (client->breakpoints[i].source && 
            client->breakpoints[i].source->path &&
            strcmp(client->breakpoints[i].source->path, source_path) == 0) {
            
            // Do a deep copy of the breakpoint
            memcpy(&breakpoints[index], &client->breakpoints[i], sizeof(DAPBreakpoint));
            
            // Allocate and copy strings
            if (client->breakpoints[i].message) {
                breakpoints[index].message = strdup(client->breakpoints[i].message);
                if (!breakpoints[index].message) {
                    goto error_cleanup;
                }
            } else {
                breakpoints[index].message = NULL;
            }
            
            if (client->breakpoints[i].source) {
                breakpoints[index].source = malloc(sizeof(DAPSource));
                if (!breakpoints[index].source) {
                    goto error_cleanup;
                }
                
                memset(breakpoints[index].source, 0, sizeof(DAPSource));
                
                if (client->breakpoints[i].source->name) {
                    breakpoints[index].source->name = 
                        strdup(client->breakpoints[i].source->name);
                    if (!breakpoints[index].source->name) {
                        goto error_cleanup;
                    }
                } else {
                    breakpoints[index].source->name = NULL;
                }
                
                if (client->breakpoints[i].source->path) {
                    breakpoints[index].source->path = 
                        strdup(client->breakpoints[i].source->path);
                    if (!breakpoints[index].source->path) {
                        goto error_cleanup;
                    }
                } else {
                    breakpoints[index].source->path = NULL;
                }
            } else {
                breakpoints[index].source = NULL;
            }
            
            if (client->breakpoints[i].condition) {
                breakpoints[index].condition = strdup(client->breakpoints[i].condition);
                if (!breakpoints[index].condition) {
                    goto error_cleanup;
                }
            } else {
                breakpoints[index].condition = NULL;
            }
            
            if (client->breakpoints[i].hit_condition) {
                breakpoints[index].hit_condition = strdup(client->breakpoints[i].hit_condition);
                if (!breakpoints[index].hit_condition) {
                    goto error_cleanup;
                }
            } else {
                breakpoints[index].hit_condition = NULL;
            }
            
            if (client->breakpoints[i].log_message) {
                breakpoints[index].log_message = strdup(client->breakpoints[i].log_message);
                if (!breakpoints[index].log_message) {
                    goto error_cleanup;
                }
            } else {
                breakpoints[index].log_message = NULL;
            }
            
            index++;
        }
    }
    
    return breakpoints;
    
error_cleanup:
    // Free everything we've allocated so far
    for (int i = 0; i < index; i++) {
        free(breakpoints[i].message);
        
        if (breakpoints[i].source) {
            free(breakpoints[i].source->name);
            free(breakpoints[i].source->path);
            free(breakpoints[i].source);
        }
        
        free(breakpoints[i].condition);
        free(breakpoints[i].hit_condition);
        free(breakpoints[i].log_message);
    }
    
    free(breakpoints);
    *count = 0;
    return NULL;
}

/**
 * @brief Set a breakpoint at a specific line
 *
 * This is a convenience function that wraps dap_client_set_breakpoints to set
 * a single breakpoint at a given line in a source file.
 *
 * @param client Pointer to the client
 * @param source_path Source file path
 * @param line Line number to set breakpoint at
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_break(DAPClient* client, const char* source_path, int line, 
                   DAPSetBreakpointsResult* result) {
    if (!client || !source_path || line <= 0 || !result) {
        return DAP_ERROR_INVALID_ARG;
    }
    
    // Create a single breakpoint
    DAPSourceBreakpoint bp = {
        .line = line,
        .column = 0,  // Column is optional, use 0 to ignore
        .condition = NULL  // No condition by default
    };
    
    // Call set_breakpoints with this single breakpoint
    return dap_client_set_breakpoints(client, source_path, &bp, 1, result);
}

/**
 * @brief Update breakpoints from server response
 * 
 * @param client Pointer to the client
 * @param source_path Source file path
 * @param server_breakpoints Array of breakpoints from server
 * @param count Number of breakpoints
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_update_breakpoints(DAPClient* client, const char* source_path, 
                                const DAPBreakpoint* server_breakpoints, int count) {
    if (!client || !source_path || !server_breakpoints || count <= 0) {
        return DAP_ERROR_INVALID_ARG;
    }
    
    // Ensure client breakpoints array exists
    if (!client->breakpoints && client->num_breakpoints > 0) {
        // This is an inconsistent state - reset count
        client->num_breakpoints = 0;
    }
    
    // Remove existing breakpoints for this source
    int i = 0;
    while (i < client->num_breakpoints) {
        if (client->breakpoints[i].source && 
            client->breakpoints[i].source->path && 
            strcmp(client->breakpoints[i].source->path, source_path) == 0) {
            // Free resources for this breakpoint
            dap_breakpoint_free(&client->breakpoints[i]);
            
            // Move the last breakpoint to this position
            if (i < client->num_breakpoints - 1) {
                memcpy(&client->breakpoints[i], 
                      &client->breakpoints[client->num_breakpoints - 1],
                       sizeof(DAPBreakpoint));
            }
            client->num_breakpoints--;
        } else {
            i++;
        }
    }
    
    // Ensure we have enough capacity for new breakpoints
    int current_capacity = client->num_breakpoints > 0 ? client->num_breakpoints : 0;
    if (client->num_breakpoints + count > current_capacity) {
        int new_capacity = current_capacity;
        if (new_capacity == 0) {
            new_capacity = 16;  // Initial capacity
        }
        while (client->num_breakpoints + count > new_capacity) {
            new_capacity *= 2;
        }
        
        // Resize array
        DAPBreakpoint* new_breakpoints = (DAPBreakpoint*)realloc(
            client->breakpoints, 
            new_capacity * sizeof(DAPBreakpoint)
        );
        
        if (!new_breakpoints) {
            return DAP_ERROR_MEMORY;
        }
        
        client->breakpoints = new_breakpoints;
    }
    
    // Add new breakpoints
    for (int i = 0; i < count; i++) {
        // Initialize all fields to NULL/0 first
        memset(&client->breakpoints[client->num_breakpoints], 0, sizeof(DAPBreakpoint));
        
        // Copy basic fields
        client->breakpoints[client->num_breakpoints].id = server_breakpoints[i].id;
        client->breakpoints[client->num_breakpoints].verified = server_breakpoints[i].verified;
        client->breakpoints[client->num_breakpoints].line = server_breakpoints[i].line;
        client->breakpoints[client->num_breakpoints].column = server_breakpoints[i].column;
        client->breakpoints[client->num_breakpoints].end_line = server_breakpoints[i].end_line;
        client->breakpoints[client->num_breakpoints].end_column = server_breakpoints[i].end_column;
        
        // Deep copy the source
        if (server_breakpoints[i].source) {
            client->breakpoints[client->num_breakpoints].source = calloc(1, sizeof(DAPSource));
            if (!client->breakpoints[client->num_breakpoints].source) {
                return DAP_ERROR_MEMORY;
            }
            
            if (server_breakpoints[i].source->name) {
                client->breakpoints[client->num_breakpoints].source->name = 
                    strdup(server_breakpoints[i].source->name);
                if (!client->breakpoints[client->num_breakpoints].source->name) {
                    return DAP_ERROR_MEMORY;
                }
            }
            
            if (server_breakpoints[i].source->path) {
                client->breakpoints[client->num_breakpoints].source->path = 
                    strdup(server_breakpoints[i].source->path);
                if (!client->breakpoints[client->num_breakpoints].source->path) {
                    return DAP_ERROR_MEMORY;
                }
            }
            
            client->breakpoints[client->num_breakpoints].source->source_reference = 
                server_breakpoints[i].source->source_reference;
        }
        
        // Deep copy message if present
        if (server_breakpoints[i].message) {
            client->breakpoints[client->num_breakpoints].message = 
                strdup(server_breakpoints[i].message);
            if (!client->breakpoints[client->num_breakpoints].message) {
                return DAP_ERROR_MEMORY;
            }
        }
        
        // Deep copy condition if present
        if (server_breakpoints[i].condition) {
            client->breakpoints[client->num_breakpoints].condition = 
                strdup(server_breakpoints[i].condition);
            if (!client->breakpoints[client->num_breakpoints].condition) {
                return DAP_ERROR_MEMORY;
            }
        }
        
        // Deep copy hit condition if present
        if (server_breakpoints[i].hit_condition) {
            client->breakpoints[client->num_breakpoints].hit_condition = 
                strdup(server_breakpoints[i].hit_condition);
            if (!client->breakpoints[client->num_breakpoints].hit_condition) {
                return DAP_ERROR_MEMORY;
            }
        }
        
        // Deep copy log message if present
        if (server_breakpoints[i].log_message) {
            client->breakpoints[client->num_breakpoints].log_message = 
                strdup(server_breakpoints[i].log_message);
            if (!client->breakpoints[client->num_breakpoints].log_message) {
                return DAP_ERROR_MEMORY;
            }
        }
        
        client->num_breakpoints++;
    }
    
    return 0;
}

/**
 * @brief Get a breakpoint by its ID
 * 
 * @param client Pointer to the client
 * @param id Breakpoint ID to find
 * @return DAPBreakpoint* Pointer to the found breakpoint, NULL if not found
 */
DAPBreakpoint* dap_client_get_breakpoint_by_id(DAPClient* client, int id) {
    if (!client || id <= 0 || !client->breakpoints || client->num_breakpoints <= 0) {
        return NULL;
    }
    
    for (int i = 0; i < client->num_breakpoints; i++) {
        if (client->breakpoints[i].id == id) {
            return &client->breakpoints[i];
        }
    }
    
    return NULL;
}

/**
 * Free resources associated with a breakpoint
 * 
 * @param breakpoint Breakpoint to free resources for
 */
void dap_breakpoint_free(DAPBreakpoint* breakpoint) {
    if (!breakpoint) return;
    
    free(breakpoint->message);
    breakpoint->message = NULL;
    
    if (breakpoint->source) {
        free(breakpoint->source->name);
        free(breakpoint->source->path);
        free(breakpoint->source);
        breakpoint->source = NULL;
    }
    
    free(breakpoint->condition);
    breakpoint->condition = NULL;
    
    free(breakpoint->hit_condition);
    breakpoint->hit_condition = NULL;
    
    free(breakpoint->log_message);
    breakpoint->log_message = NULL;
}

/**
 * @brief Process a received DAP event
 * 
 * @param client Pointer to the client
 * @param event_json JSON object containing the event data
 * @return int 0 on success, -1 on failure
 */
int dap_client_handle_event(DAPClient* client, cJSON* event_json) {
    if (!client || !event_json) {
        return -1;
    }
    
    // Extract event type
    cJSON* event_type = cJSON_GetObjectItem(event_json, "event");
    if (!event_type || !cJSON_IsString(event_type)) {
        DAP_CLIENT_DEBUG_LOG("Invalid event: missing 'event' field");
        return -1;
    }
    
    const char* event_name = event_type->valuestring;
    
    // Extract event body if present
    cJSON* body = cJSON_GetObjectItem(event_json, "body");
    
    // Log the event
    DAP_CLIENT_DEBUG_LOG("Received event: %s", event_name);
    
    // Process different event types
    if (strcmp(event_name, "initialized") == 0) {
        // Handle initialized event
        DAP_CLIENT_DEBUG_LOG("Debug adapter initialized");
        // Additional processing if needed
    } 
    else if (strcmp(event_name, "stopped") == 0) {
        // Handle stopped event
        if (body) {
            cJSON* reason = cJSON_GetObjectItem(body, "reason");
            cJSON* thread_id = cJSON_GetObjectItem(body, "threadId");
            
            if (reason && cJSON_IsString(reason)) {
                if (thread_id && cJSON_IsNumber(thread_id)) {
                    DAP_CLIENT_DEBUG_LOG("Thread %d stopped: %s", 
                                      thread_id->valueint, 
                                      reason->valuestring);
                } else {
                    DAP_CLIENT_DEBUG_LOG("Program stopped: %s", 
                                      reason->valuestring);
                }
            }
        }
    }
    else if (strcmp(event_name, "continued") == 0) {
        // Handle continued event
        if (body) {
            cJSON* thread_id = cJSON_GetObjectItem(body, "threadId");
            cJSON* all_threads_continued = cJSON_GetObjectItem(body, "allThreadsContinued");
            
            if (thread_id && cJSON_IsNumber(thread_id)) {
                if (all_threads_continued && cJSON_IsTrue(all_threads_continued)) {
                    DAP_CLIENT_DEBUG_LOG("All threads continued");
                } else {
                    DAP_CLIENT_DEBUG_LOG("Thread %d continued", thread_id->valueint);
                }
            }
        }
    }
    else if (strcmp(event_name, "exited") == 0) {
        // Handle exited event
        if (body) {
            cJSON* exit_code = cJSON_GetObjectItem(body, "exitCode");
            
            if (exit_code && cJSON_IsNumber(exit_code)) {
                DAP_CLIENT_DEBUG_LOG("Program exited with code %d", exit_code->valueint);
            }
        }
    }
    else if (strcmp(event_name, "terminated") == 0) {
        // Handle terminated event
        DAP_CLIENT_DEBUG_LOG("Debug adapter terminated");
    }
    else if (strcmp(event_name, "thread") == 0) {
        // Handle thread event
        if (body) {
            cJSON* reason = cJSON_GetObjectItem(body, "reason");
            cJSON* thread_id = cJSON_GetObjectItem(body, "threadId");
            
            if (reason && cJSON_IsString(reason) && 
                thread_id && cJSON_IsNumber(thread_id)) {
                DAP_CLIENT_DEBUG_LOG("Thread %d: %s", 
                                  thread_id->valueint, 
                                  reason->valuestring);
            }
        }
    }
    else if (strcmp(event_name, "output") == 0) {
        // Handle output event
        if (body) {
            cJSON* output = cJSON_GetObjectItem(body, "output");
            cJSON* category = cJSON_GetObjectItem(body, "category");
            
            if (output && cJSON_IsString(output)) {
                const char* category_str = category && cJSON_IsString(category) 
                                        ? category->valuestring 
                                        : "console";
                                        
                DAP_CLIENT_DEBUG_LOG("[%s] %s", category_str, output->valuestring);
            }
        }
    }
    else if (strcmp(event_name, "breakpoint") == 0) {
        // Handle breakpoint event
        if (body) {
            cJSON* reason = cJSON_GetObjectItem(body, "reason");
            cJSON* breakpoint = cJSON_GetObjectItem(body, "breakpoint");
            
            if (reason && cJSON_IsString(reason) && breakpoint) {
                cJSON* id = cJSON_GetObjectItem(breakpoint, "id");
                if (id && cJSON_IsNumber(id)) {
                    DAP_CLIENT_DEBUG_LOG("Breakpoint %d: %s", 
                                      id->valueint, 
                                      reason->valuestring);
                }
            }
        }
    }
    // Additional event types can be handled here
    
    return 0;
}
