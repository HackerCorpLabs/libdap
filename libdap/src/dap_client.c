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
#include "cJSON.h"
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
    client->data_breakpoints = NULL;
    client->num_data_breakpoints = 0;
    
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
    
    // Free tracked breakpoints
    dap_client_clear_breakpoints(client);

    // Free tracked data breakpoints (watchpoints)
    dap_client_clear_data_breakpoints(client);
    
    // Free client structure
    free(client);
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
 * @brief Read memory from the debuggee
 * 
 * @param client Pointer to the client
 * @param memory_reference Memory reference to read from
 * @param offset Offset from the memory reference
 * @param count Number of bytes to read
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_read_memory(DAPClient* client, uint32_t memory_reference, uint32_t offset, size_t count, DAPReadMemoryResult* result) {
    if (!client || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    // Convert memory_reference to string (needed for DAP protocol)
    char memory_ref_str[32];
    snprintf(memory_ref_str, sizeof(memory_ref_str), "0x%x", memory_reference);
    cJSON_AddStringToObject(args, "memoryReference", memory_ref_str);
    
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
int dap_client_write_memory(DAPClient* client, uint32_t memory_reference, uint32_t offset, const char* data, bool allow_partial, DAPWriteMemoryResult* result) {
    if (!client || !data || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    // Convert memory_reference to string (needed for DAP protocol)
    char memory_ref_str[32];
    snprintf(memory_ref_str, sizeof(memory_ref_str), "0x%x", memory_reference);
    cJSON_AddStringToObject(args, "memoryReference", memory_ref_str);
    
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
    result->offset = offset_result ? (uint32_t)offset_result->valueint : offset;

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
int dap_client_disassemble(DAPClient* client, uint32_t memory_reference, uint32_t offset, size_t instruction_offset, size_t instruction_count, bool resolve_symbols, DAPDisassembleResult* result) {
    if (!client || !result) {
        return DAP_ERROR_INVALID_ARG;
    }

    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }

    // Format memory reference as a hex string
    char memory_ref_str[32];
    snprintf(memory_ref_str, sizeof(memory_ref_str), "0x%08x", memory_reference);
    cJSON_AddStringToObject(args, "memoryReference", memory_ref_str);
    
    // Add optional parameters
    if (offset > 0) {
        cJSON_AddNumberToObject(args, "offset", (double)offset);
    }
    
    if (instruction_offset > 0) {
        cJSON_AddNumberToObject(args, "instructionOffset", (double)instruction_offset);
    }
    
    cJSON_AddNumberToObject(args, "instructionCount", (double)instruction_count);
    cJSON_AddBoolToObject(args, "resolveSymbols", resolve_symbols);

    // Initialize result struct
    memset(result, 0, sizeof(DAPDisassembleResult));
    
    // Send request
    char* response_body = NULL;
    int err = dap_client_send_request(client, DAP_CMD_DISASSEMBLE, args, &response_body);
    cJSON_Delete(args);
    
    if (err != DAP_ERROR_NONE) {
        return err;
    }
    
    if (!response_body) {
        return DAP_ERROR_INVALID_FORMAT;
    }
    
    // Parse response
    cJSON* root = cJSON_Parse(response_body);
    free(response_body);
    
    if (!root) {
        return DAP_ERROR_PARSE_ERROR;
    }
    
    // Get body
    cJSON* body = cJSON_GetObjectItem(root, "body");
    if (!body) {
        cJSON_Delete(root);
        return DAP_ERROR_INVALID_FORMAT;
    }
    
    // Get instructions array
    cJSON* instructions_json = cJSON_GetObjectItem(body, "instructions");
    if (!instructions_json || !cJSON_IsArray(instructions_json)) {
        cJSON_Delete(root);
        return DAP_ERROR_INVALID_FORMAT;
    }
    
    // Count instructions
    int count = cJSON_GetArraySize(instructions_json);
    if (count <= 0) {
        cJSON_Delete(root);
        result->instructions = NULL;
        result->num_instructions = 0;
        return DAP_ERROR_NONE;
    }
    
    // Allocate instructions array
    result->instructions = calloc(count, sizeof(DAPDisassembledInstruction));
    if (!result->instructions) {
        cJSON_Delete(root);
        return DAP_ERROR_MEMORY;
    }
    
    result->num_instructions = count;
    int i;
    // Parse each instruction
    for (i = 0; i < count; i++) {
        cJSON* instr = cJSON_GetArrayItem(instructions_json, i);
        if (!instr) continue;
        
        cJSON* address = cJSON_GetObjectItem(instr, "address");
        if (address && cJSON_IsString(address)) {
            result->instructions[i].address = strdup(address->valuestring);
        }
        
        cJSON* instruction_text = cJSON_GetObjectItem(instr, "instruction");
        if (instruction_text && cJSON_IsString(instruction_text)) {
            result->instructions[i].instruction = strdup(instruction_text->valuestring);
        }
        
        // Optional fields
        cJSON* symbol = cJSON_GetObjectItem(instr, "symbol");
        if (symbol && cJSON_IsString(symbol)) {
            result->instructions[i].symbol = strdup(symbol->valuestring);
        }
    }
    
    cJSON_Delete(root);
    return DAP_ERROR_NONE;

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
    if (!client || !frames || !frame_count) {
        return DAP_ERROR_INVALID_ARG;
    }

    *frames = NULL;
    *frame_count = 0;

    cJSON* args = cJSON_CreateObject();
    if (!args) return DAP_ERROR_MEMORY;

    cJSON_AddNumberToObject(args, "threadId", thread_id);
    cJSON_AddNumberToObject(args, "startFrame", 0);
    cJSON_AddNumberToObject(args, "levels", 20);

    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_STACK_TRACE, args, &response);
    cJSON_Delete(args);

    if (error != DAP_ERROR_NONE) {
        return error;
    }
    if (!response) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* json = cJSON_Parse(response);
    free(response);
    if (!json) {
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* success = cJSON_GetObjectItem(json, "success");
    if (!success || !cJSON_IsTrue(success)) {
        cJSON_Delete(json);
        return DAP_ERROR_REQUEST_FAILED;
    }

    cJSON* body = cJSON_GetObjectItem(json, "body");
    if (!body) {
        cJSON_Delete(json);
        return DAP_ERROR_PARSE_ERROR;
    }

    cJSON* stack_frames = cJSON_GetObjectItem(body, "stackFrames");
    if (!stack_frames || !cJSON_IsArray(stack_frames)) {
        cJSON_Delete(json);
        return DAP_ERROR_PARSE_ERROR;
    }

    int count = cJSON_GetArraySize(stack_frames);
    if (count == 0) {
        cJSON_Delete(json);
        return DAP_ERROR_NONE;
    }

    DAPStackFrame* result = calloc(count, sizeof(DAPStackFrame));
    if (!result) {
        cJSON_Delete(json);
        return DAP_ERROR_MEMORY;
    }

    for (int i = 0; i < count; i++) {
        cJSON* frame = cJSON_GetArrayItem(stack_frames, i);

        cJSON* id = cJSON_GetObjectItem(frame, "id");
        cJSON* name = cJSON_GetObjectItem(frame, "name");
        cJSON* line = cJSON_GetObjectItem(frame, "line");
        cJSON* column = cJSON_GetObjectItem(frame, "column");
        cJSON* ipr = cJSON_GetObjectItem(frame, "instructionPointerReference");

        result[i].id = id ? id->valueint : i;
        result[i].name = name && name->valuestring ? strdup(name->valuestring) : NULL;
        result[i].line = line ? line->valueint : 0;
        result[i].column = column ? column->valueint : 0;

        if (ipr && ipr->valuestring) {
            result[i].instruction_pointer_reference = (int)strtoul(ipr->valuestring, NULL, 0);
        }

        cJSON* source = cJSON_GetObjectItem(frame, "source");
        if (source) {
            cJSON* path = cJSON_GetObjectItem(source, "path");
            cJSON* sname = cJSON_GetObjectItem(source, "name");
            result[i].source_path = path && path->valuestring ? strdup(path->valuestring) : NULL;
            result[i].source_name = sname && sname->valuestring ? strdup(sname->valuestring) : NULL;
        }
    }

    *frames = result;
    *frame_count = count;

    cJSON_Delete(json);
    return DAP_ERROR_NONE;
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
    cJSON_AddBoolToObject(capabilities, "supportTerminateDebuggee", true); // NOTE! This is not the same as terminateRequest. And be aware of the single vs plural in the name. Its single!
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

        // Skip scopes without name or variablesReference (server may send empty entries)
        if (!name || !name->valuestring || !variables_reference) {
            result->scopes[i].name = strdup("");
            result->scopes[i].variables_reference = 0;
            continue;
        }

        result->scopes[i].name = strdup(name->valuestring);
        result->scopes[i].variables_reference = variables_reference->valueint;
        result->scopes[i].named_variables = named_variables ? named_variables->valueint : 0;
        result->scopes[i].indexed_variables = indexed_variables ? indexed_variables->valueint : 0;
        result->scopes[i].expensive = expensive ? cJSON_IsTrue(expensive) : false;

        // capture source.name and source.path?
        if (source) {
/*            
            cJSON* name = cJSON_GetObjectItem(source, "name");
            cJSON* path = cJSON_GetObjectItem(source, "path");
            if (name) {
                result->scopes[i].source_name = strdup(name->valuestring);
            }
  */          
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
            free(var->evaluate_name);
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
        if (named_variables && cJSON_IsNumber(named_variables)) {
            var->named_variables = named_variables->valueint;
        } else {
            var->named_variables = 0; // Default value
        }

        cJSON* indexed_variables = cJSON_GetObjectItem(variable_item, "indexedVariables");
        if (indexed_variables && cJSON_IsNumber(indexed_variables)) {
            var->indexed_variables = indexed_variables->valueint;
        } else {
            var->indexed_variables = 0; // Default value
        }

        cJSON* memory_reference = cJSON_GetObjectItem(variable_item, "memoryReference");
        if (memory_reference && cJSON_IsString(memory_reference)) {
            // Convert the memoryReference string to uint32_t
            unsigned int mem_ref_val = 0;
            sscanf(memory_reference->valuestring, "0x%x", &mem_ref_val);
            var->memory_reference = (uint32_t)mem_ref_val;
        }

        var->presentation_hint.kind = DAP_VARIABLE_KIND_NONE;            
        var->presentation_hint.attributes = DAP_VARIABLE_ATTR_NONE;
        var->presentation_hint.visibility = DAP_VARIABLE_VISIBILITY_NONE;

        cJSON* presentation_hint = cJSON_GetObjectItem(variable_item, "presentationHint");
        if (presentation_hint) {
            // Parse presentation hint as an object according to DAP spec
            cJSON* kind = cJSON_GetObjectItem(presentation_hint, "kind");
            if (kind && cJSON_IsString(kind)) {
                var->presentation_hint.kind = DAP_VARIABLE_KIND_NONE; // When no kind is present
                
                // Map the kind string to our enum
                const char* kind_str = kind->valuestring;
                if (strcmp(kind_str, "property") == 0) {
                    var->presentation_hint.kind = DAP_VARIABLE_KIND_PROPERTY;
                } else if (strcmp(kind_str, "method") == 0) {
                    var->presentation_hint.kind = DAP_VARIABLE_KIND_METHOD;
                } else if (strcmp(kind_str, "class") == 0) {
                    var->presentation_hint.kind = DAP_VARIABLE_KIND_CLASS;
                } else if (strcmp(kind_str, "data") == 0) {
                    var->presentation_hint.kind = DAP_VARIABLE_KIND_DATA;
                } else if (strcmp(kind_str, "event") == 0) {
                    var->presentation_hint.kind = DAP_VARIABLE_KIND_EVENT;
                } else if (strcmp(kind_str, "baseClass") == 0) {
                    var->presentation_hint.kind = DAP_VARIABLE_KIND_BASE_CLASS;
                } else if (strcmp(kind_str, "innerClass") == 0) {
                    var->presentation_hint.kind = DAP_VARIABLE_KIND_INNER_CLASS;
                } else if (strcmp(kind_str, "interface") == 0) {
                    var->presentation_hint.kind = DAP_VARIABLE_KIND_INTERFACE;
                } else if (strcmp(kind_str, "mostDerivedClass") == 0) {
                    var->presentation_hint.kind = DAP_VARIABLE_KIND_MOST_DERIVED;
                } else if (strcmp(kind_str, "virtual") == 0) {
                    var->presentation_hint.kind = DAP_VARIABLE_KIND_VIRTUAL;
                } else if (strcmp(kind_str, "dataBreakpoint") == 0) {
                    var->presentation_hint.kind = DAP_VARIABLE_KIND_DATABREAKPOINT;
                }
            }
            
            // Parse attributes array
            cJSON* attributes = cJSON_GetObjectItem(presentation_hint, "attributes");
            if (attributes && cJSON_IsArray(attributes)) {
                var->presentation_hint.attributes = DAP_VARIABLE_ATTR_NONE;
                
                int array_size = cJSON_GetArraySize(attributes);
                for (int j = 0; j < array_size; j++) {
                    cJSON* attr = cJSON_GetArrayItem(attributes, j);
                    if (attr && cJSON_IsString(attr)) {
                        const char* attr_str = attr->valuestring;
                        if (strcmp(attr_str, "static") == 0) {
                            var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_STATIC;
                        } else if (strcmp(attr_str, "constant") == 0) {
                            var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_CONSTANT;
                        } else if (strcmp(attr_str, "readOnly") == 0) {
                            var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_READONLY;
                        } else if (strcmp(attr_str, "rawString") == 0) {
                            var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_RAWSTRING;
                        } else if (strcmp(attr_str, "hasObjectId") == 0) {
                            var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_HASOBJECTID;
                        } else if (strcmp(attr_str, "canHaveObjectId") == 0) {
                            var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_CANHAVEOBJECTID;
                        } else if (strcmp(attr_str, "hasSideEffects") == 0) {
                            var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_HASSIDEEFFECTS;
                        } else if (strcmp(attr_str, "hasDataBreakpoint") == 0) { 
                            var->presentation_hint.attributes |= DAP_VARIABLE_ATTR_HASDATABREAKPOINT;
                        }
                    }
                }
            }
            
            // Parse visibility
            cJSON* visibility = cJSON_GetObjectItem(presentation_hint, "visibility");
            if (visibility && cJSON_IsString(visibility)) {
                
                
                const char* visibility_str = visibility->valuestring;
                if (strcmp(visibility_str, "public") == 0) {
                    var->presentation_hint.visibility = DAP_VARIABLE_VISIBILITY_PUBLIC;
                } else if (strcmp(visibility_str, "private") == 0) {
                    var->presentation_hint.visibility = DAP_VARIABLE_VISIBILITY_PRIVATE;
                } else if (strcmp(visibility_str, "protected") == 0) {
                    var->presentation_hint.visibility = DAP_VARIABLE_VISIBILITY_PROTECTED;
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
        }
        free(result->instructions);
    }

    result->instructions = NULL;
    result->num_instructions = 0;
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

/**
 * @brief Set exception breakpoints
 *
 * @param client Pointer to the client
 * @param filters Array of exception filter IDs
 * @param num_filters Number of filters
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_set_exception_breakpoints(DAPClient* client, 
                                       const char** filters, size_t num_filters,
                                       DAPSetExceptionBreakpointsResult* result) {
    if (!client || !result) {
        return DAP_ERROR_INVALID_ARG;
    }
    
    // Initialize result structure
    result->base.success = false;
    result->base.message = NULL;
    result->breakpoints = NULL;
    result->num_breakpoints = 0;
    
    // Create arguments object
    cJSON* args = cJSON_CreateObject();
    if (!args) {
        return DAP_ERROR_MEMORY;
    }
    
    // Create filters array
    cJSON* filters_array = cJSON_CreateArray();
    if (!filters_array) {
        cJSON_Delete(args);
        return DAP_ERROR_MEMORY;
    }
    
    // Add filters to the array
    for (size_t i = 0; i < num_filters; i++) {
        if (filters[i]) {
            cJSON* filter = cJSON_CreateString(filters[i]);
            if (!filter) {
                cJSON_Delete(args);
                return DAP_ERROR_MEMORY;
            }
            cJSON_AddItemToArray(filters_array, filter);
        }
    }
    
    // Add filters array to arguments
    cJSON_AddItemToObject(args, "filters", filters_array);
    
    // Send the request
    char* response = NULL;
    int error = dap_client_send_request(client, DAP_CMD_SET_EXCEPTION_BREAKPOINTS, args, &response);
    cJSON_Delete(args);
    
    if (error != DAP_ERROR_NONE) {
        return error;
    }
    
    // Parse the response
    if (!response) {
        return DAP_ERROR_PARSE_ERROR;
    }
    
    // Parse the response JSON
    cJSON* root = cJSON_Parse(response);
    free(response);
    
    if (!root) {
        return DAP_ERROR_PARSE_ERROR;
    }
    
    // Check for success
    cJSON* success = cJSON_GetObjectItem(root, "success");
    if (!success || !cJSON_IsBool(success) || !cJSON_IsTrue(success)) {
        cJSON* message = cJSON_GetObjectItem(root, "message");
        if (message && cJSON_IsString(message)) {
            result->base.message = strdup(message->valuestring);
        }
        cJSON_Delete(root);
        return DAP_ERROR_REQUEST_FAILED;
    }
    
    result->base.success = true;
    
    // Parse breakpoints from the response body
    cJSON* body = cJSON_GetObjectItem(root, "body");
    if (!body) {
        // No body is valid for this response
        cJSON_Delete(root);
        return DAP_ERROR_NONE;
    }
    
    cJSON* breakpoints = cJSON_GetObjectItem(body, "breakpoints");
    if (!breakpoints || !cJSON_IsArray(breakpoints)) {
        // No breakpoints is valid for this response
        cJSON_Delete(root);
        return DAP_ERROR_NONE;
    }
    
    // Count breakpoints
    int num_breakpoints = cJSON_GetArraySize(breakpoints);
    if (num_breakpoints <= 0) {
        cJSON_Delete(root);
        return DAP_ERROR_NONE;
    }
    
    // Allocate memory for breakpoints
    result->breakpoints = calloc(num_breakpoints, sizeof(DAPBreakpoint));
    if (!result->breakpoints) {
        cJSON_Delete(root);
        return DAP_ERROR_MEMORY;
    }
    result->num_breakpoints = num_breakpoints;
    
    // Parse each breakpoint
    for (int i = 0; i < num_breakpoints; i++) {
        cJSON* bp = cJSON_GetArrayItem(breakpoints, i);
        if (!bp) {
            continue;
        }
        
        cJSON* id = cJSON_GetObjectItem(bp, "id");
        if (id && cJSON_IsNumber(id)) {
            result->breakpoints[i].id = id->valueint;
        }
        
        cJSON* verified = cJSON_GetObjectItem(bp, "verified");
        if (verified && cJSON_IsBool(verified)) {
            result->breakpoints[i].verified = cJSON_IsTrue(verified);
        }
        
        cJSON* message = cJSON_GetObjectItem(bp, "message");
        if (message && cJSON_IsString(message)) {
            result->breakpoints[i].message = strdup(message->valuestring);
        }
    }

    cJSON_Delete(root);
    return DAP_ERROR_NONE;
}

// ---------------------------------------------------------------------------
// Breakpoint tracking API
// ---------------------------------------------------------------------------

void dap_client_clear_breakpoints(DAPClient* client) {
    if (!client || !client->breakpoints) return;

    for (int i = 0; i < client->num_breakpoints; i++) {
        free(client->breakpoints[i].message);
        free(client->breakpoints[i].condition);
        free(client->breakpoints[i].hit_condition);
        free(client->breakpoints[i].log_message);
        free(client->breakpoints[i].source_path);
        free(client->breakpoints[i].source_name);
    }
    free(client->breakpoints);
    client->breakpoints = NULL;
    client->num_breakpoints = 0;
}

void dap_client_clear_data_breakpoints(DAPClient* client) {
    if (!client || !client->data_breakpoints) return;

    for (int i = 0; i < client->num_data_breakpoints; i++) {
        free(client->data_breakpoints[i].data_id);
        free(client->data_breakpoints[i].condition);
        free(client->data_breakpoints[i].hit_condition);
        free(client->data_breakpoints[i].message);
    }
    free(client->data_breakpoints);
    client->data_breakpoints = NULL;
    client->num_data_breakpoints = 0;
}

const DAPBreakpoint* dap_client_get_breakpoints(DAPClient* client, int* count) {
    if (!client) {
        if (count) *count = 0;
        return NULL;
    }
    if (count) *count = client->num_breakpoints;
    return client->breakpoints;
}

const DAPDataBreakpoint* dap_client_get_data_breakpoints(DAPClient* client, int* count) {
    if (!client) {
        if (count) *count = 0;
        return NULL;
    }
    if (count) *count = client->num_data_breakpoints;
    return client->data_breakpoints;
}

int dap_client_set_breakpoints(DAPClient* client, const char* source_path,
                               const DAPSourceBreakpoint* source_breakpoints,
                               int count, DAPSetBreakpointsResult* result) {
    if (!client || !source_path || !result)
        return DAP_ERROR_INVALID_ARG;

    result->base.success = false;
    result->base.message = NULL;
    result->breakpoints = NULL;
    result->num_breakpoints = 0;

    // Build merged breakpoint list: existing for this source + new ones
    int existing_for_source = 0;
    for (int i = 0; i < client->num_breakpoints; i++) {
        if (client->breakpoints[i].source_path &&
            strcmp(client->breakpoints[i].source_path, source_path) == 0)
            existing_for_source++;
    }

    int merged_count = existing_for_source + count;
    DAPSourceBreakpoint* merged = calloc(merged_count, sizeof(DAPSourceBreakpoint));
    if (!merged) return DAP_ERROR_MEMORY;

    // Copy existing breakpoints for this source
    int mi = 0;
    for (int i = 0; i < client->num_breakpoints; i++) {
        if (client->breakpoints[i].source_path &&
            strcmp(client->breakpoints[i].source_path, source_path) == 0) {
            merged[mi].line = client->breakpoints[i].line;
            merged[mi].condition = client->breakpoints[i].condition;       // borrow, don't strdup
            merged[mi].hit_condition = client->breakpoints[i].hit_condition;
            merged[mi].log_message = client->breakpoints[i].log_message;
            mi++;
        }
    }
    // Append new breakpoints
    for (int i = 0; i < count; i++) {
        merged[mi].line = source_breakpoints[i].line;
        merged[mi].condition = source_breakpoints[i].condition;
        merged[mi].hit_condition = source_breakpoints[i].hit_condition;
        merged[mi].log_message = source_breakpoints[i].log_message;
        mi++;
    }

    // Build JSON request from merged list
    cJSON* args = cJSON_CreateObject();
    if (!args) { free(merged); return DAP_ERROR_MEMORY; }

    cJSON* source_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(source_obj, "path", source_path);
    cJSON_AddItemToObject(args, "source", source_obj);

    cJSON* bp_array = cJSON_CreateArray();
    for (int i = 0; i < merged_count; i++) {
        cJSON* bp = cJSON_CreateObject();
        cJSON_AddNumberToObject(bp, "line", merged[i].line);
        if (merged[i].condition)
            cJSON_AddStringToObject(bp, "condition", merged[i].condition);
        if (merged[i].hit_condition)
            cJSON_AddStringToObject(bp, "hitCondition", merged[i].hit_condition);
        if (merged[i].log_message)
            cJSON_AddStringToObject(bp, "logMessage", merged[i].log_message);
        cJSON_AddItemToArray(bp_array, bp);
    }
    cJSON_AddItemToObject(args, "breakpoints", bp_array);

    char* response = NULL;
    int err = dap_client_send_request(client, DAP_CMD_SET_BREAKPOINTS, args, &response);
    cJSON_Delete(args);

    if (err != DAP_ERROR_NONE) {
        free(merged);
        free(response);
        return err;
    }

    if (!response) { free(merged); return DAP_ERROR_INVALID_RESPONSE; }

    cJSON* root = cJSON_Parse(response);
    free(response);
    if (!root) { free(merged); return DAP_ERROR_INVALID_RESPONSE; }

    cJSON* success = cJSON_GetObjectItem(root, "success");
    if (!success || !cJSON_IsTrue(success)) {
        cJSON* msg = cJSON_GetObjectItem(root, "message");
        if (msg && msg->valuestring)
            result->base.message = strdup(msg->valuestring);
        free(merged);
        cJSON_Delete(root);
        return DAP_ERROR_INVALID_RESPONSE;
    }
    result->base.success = true;

    cJSON* body = cJSON_GetObjectItem(root, "body");
    cJSON* bps = body ? cJSON_GetObjectItem(body, "breakpoints") : NULL;
    int num_bps = (bps && cJSON_IsArray(bps)) ? cJSON_GetArraySize(bps) : 0;

    if (num_bps > 0) {
        result->breakpoints = calloc(num_bps, sizeof(DAPBreakpoint));
        if (!result->breakpoints) {
            free(merged);
            cJSON_Delete(root);
            return DAP_ERROR_MEMORY;
        }
        result->num_breakpoints = num_bps;

        for (int i = 0; i < num_bps; i++) {
            cJSON* b = cJSON_GetArrayItem(bps, i);
            if (!b) continue;

            cJSON* id_j = cJSON_GetObjectItem(b, "id");
            if (id_j) result->breakpoints[i].id = id_j->valueint;

            cJSON* v = cJSON_GetObjectItem(b, "verified");
            result->breakpoints[i].verified = v ? cJSON_IsTrue(v) : false;

            cJSON* line_j = cJSON_GetObjectItem(b, "line");
            if (line_j) result->breakpoints[i].line = line_j->valueint;

            cJSON* msg = cJSON_GetObjectItem(b, "message");
            if (msg && msg->valuestring)
                result->breakpoints[i].message = strdup(msg->valuestring);

            cJSON* ipr = cJSON_GetObjectItem(b, "instructionReference");
            if (ipr && ipr->valuestring)
                result->breakpoints[i].instruction_reference = (uint32_t)strtoul(ipr->valuestring, NULL, 0);

            result->breakpoints[i].source_path = strdup(source_path);
        }
    }

    // Update client tracking: remove old breakpoints for this source, add new ones
    int keep = 0;
    for (int i = 0; i < client->num_breakpoints; i++) {
        if (client->breakpoints[i].source_path &&
            strcmp(client->breakpoints[i].source_path, source_path) != 0)
            keep++;
    }

    int new_total = keep + num_bps;
    DAPBreakpoint* new_list = NULL;
    if (new_total > 0) {
        new_list = calloc(new_total, sizeof(DAPBreakpoint));
        if (!new_list) {
            free(merged);
            cJSON_Delete(root);
            return DAP_ERROR_MEMORY;
        }

        // Copy breakpoints from other sources
        int idx = 0;
        for (int i = 0; i < client->num_breakpoints; i++) {
            if (client->breakpoints[i].source_path &&
                strcmp(client->breakpoints[i].source_path, source_path) != 0) {
                new_list[idx] = client->breakpoints[i];
                // Transfer ownership
                client->breakpoints[i].source_path = NULL;
                client->breakpoints[i].source_name = NULL;
                client->breakpoints[i].message = NULL;
                client->breakpoints[i].condition = NULL;
                client->breakpoints[i].hit_condition = NULL;
                client->breakpoints[i].log_message = NULL;
                idx++;
            }
        }

        // Add verified breakpoints from response, conditions from merged list
        for (int i = 0; i < num_bps; i++) {
            new_list[idx].id = result->breakpoints[i].id;
            new_list[idx].verified = result->breakpoints[i].verified;
            new_list[idx].line = result->breakpoints[i].line;
            new_list[idx].source_path = strdup(source_path);
            new_list[idx].instruction_reference = result->breakpoints[i].instruction_reference;
            if (result->breakpoints[i].message)
                new_list[idx].message = strdup(result->breakpoints[i].message);
            if (i < merged_count && merged[i].condition)
                new_list[idx].condition = strdup(merged[i].condition);
            if (i < merged_count && merged[i].hit_condition)
                new_list[idx].hit_condition = strdup(merged[i].hit_condition);
            if (i < merged_count && merged[i].log_message)
                new_list[idx].log_message = strdup(merged[i].log_message);
            idx++;
        }
    }

    // Free old list (strings already transferred or freed above)
    dap_client_clear_breakpoints(client);
    client->breakpoints = new_list;
    client->num_breakpoints = new_total;

    free(merged);
    cJSON_Delete(root);
    return DAP_ERROR_NONE;
}

int dap_client_set_data_breakpoints(DAPClient* client,
                                    const DAPDataBreakpoint* data_breakpoints,
                                    int count,
                                    DAPSetDataBreakpointsResult* result) {
    if (!client || !result)
        return DAP_ERROR_INVALID_ARG;

    result->base.success = false;
    result->base.message = NULL;
    result->breakpoints = NULL;
    result->num_breakpoints = 0;

    // Build JSON request
    cJSON* args = cJSON_CreateObject();
    if (!args) return DAP_ERROR_MEMORY;

    cJSON* bp_array = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON* bp = cJSON_CreateObject();
        if (data_breakpoints[i].data_id)
            cJSON_AddStringToObject(bp, "dataId", data_breakpoints[i].data_id);

        const char* access_str = "write";
        switch (data_breakpoints[i].access_type) {
            case DAP_DATA_BP_ACCESS_READ:      access_str = "read"; break;
            case DAP_DATA_BP_ACCESS_WRITE:     access_str = "write"; break;
            case DAP_DATA_BP_ACCESS_READWRITE: access_str = "readWrite"; break;
        }
        cJSON_AddStringToObject(bp, "accessType", access_str);

        if (data_breakpoints[i].condition)
            cJSON_AddStringToObject(bp, "condition", data_breakpoints[i].condition);
        if (data_breakpoints[i].hit_condition)
            cJSON_AddStringToObject(bp, "hitCondition", data_breakpoints[i].hit_condition);

        cJSON_AddItemToArray(bp_array, bp);
    }
    cJSON_AddItemToObject(args, "breakpoints", bp_array);

    char* response = NULL;
    int err = dap_client_send_request(client, DAP_CMD_SET_DATA_BREAKPOINTS, args, &response);
    cJSON_Delete(args);

    if (err != DAP_ERROR_NONE) {
        free(response);
        return err;
    }

    if (!response) return DAP_ERROR_INVALID_RESPONSE;

    cJSON* root = cJSON_Parse(response);
    free(response);
    if (!root) return DAP_ERROR_INVALID_RESPONSE;

    cJSON* success = cJSON_GetObjectItem(root, "success");
    if (!success || !cJSON_IsTrue(success)) {
        cJSON* msg = cJSON_GetObjectItem(root, "message");
        if (msg && msg->valuestring)
            result->base.message = strdup(msg->valuestring);
        cJSON_Delete(root);
        return DAP_ERROR_INVALID_RESPONSE;
    }
    result->base.success = true;

    cJSON* body = cJSON_GetObjectItem(root, "body");
    cJSON* bps = body ? cJSON_GetObjectItem(body, "breakpoints") : NULL;
    int num_bps = (bps && cJSON_IsArray(bps)) ? cJSON_GetArraySize(bps) : 0;

    if (num_bps > 0) {
        result->breakpoints = calloc(num_bps, sizeof(DAPDataBreakpoint));
        if (!result->breakpoints) {
            cJSON_Delete(root);
            return DAP_ERROR_MEMORY;
        }
        result->num_breakpoints = num_bps;

        for (int i = 0; i < num_bps; i++) {
            cJSON* b = cJSON_GetArrayItem(bps, i);
            if (!b) continue;

            cJSON* id_j = cJSON_GetObjectItem(b, "id");
            if (id_j) result->breakpoints[i].id = id_j->valueint;

            cJSON* v = cJSON_GetObjectItem(b, "verified");
            result->breakpoints[i].verified = v ? cJSON_IsTrue(v) : false;

            cJSON* msg = cJSON_GetObjectItem(b, "message");
            if (msg && msg->valuestring)
                result->breakpoints[i].message = strdup(msg->valuestring);

            // Carry forward request data
            if (i < count) {
                if (data_breakpoints[i].data_id)
                    result->breakpoints[i].data_id = strdup(data_breakpoints[i].data_id);
                result->breakpoints[i].access_type = data_breakpoints[i].access_type;
                result->breakpoints[i].address_space = data_breakpoints[i].address_space;
                result->breakpoints[i].address = data_breakpoints[i].address;
            }
        }
    }

    // Replace client tracking with new set (DAP replaces all data breakpoints)
    dap_client_clear_data_breakpoints(client);
    if (num_bps > 0) {
        client->data_breakpoints = calloc(num_bps, sizeof(DAPDataBreakpoint));
        if (client->data_breakpoints) {
            client->num_data_breakpoints = num_bps;
            for (int i = 0; i < num_bps; i++) {
                client->data_breakpoints[i].id = result->breakpoints[i].id;
                client->data_breakpoints[i].verified = result->breakpoints[i].verified;
                if (result->breakpoints[i].data_id)
                    client->data_breakpoints[i].data_id = strdup(result->breakpoints[i].data_id);
                client->data_breakpoints[i].access_type = result->breakpoints[i].access_type;
                client->data_breakpoints[i].address_space = result->breakpoints[i].address_space;
                client->data_breakpoints[i].address = result->breakpoints[i].address;
                if (result->breakpoints[i].message)
                    client->data_breakpoints[i].message = strdup(result->breakpoints[i].message);
            }
        }
    }

    cJSON_Delete(root);
    return DAP_ERROR_NONE;
}

void dap_set_breakpoints_result_free(DAPSetBreakpointsResult* result) {
    if (!result) return;
    for (size_t i = 0; i < result->num_breakpoints; i++) {
        free(result->breakpoints[i].message);
        free(result->breakpoints[i].source_path);
        free(result->breakpoints[i].source_name);
        free(result->breakpoints[i].condition);
        free(result->breakpoints[i].hit_condition);
        free(result->breakpoints[i].log_message);
    }
    free(result->breakpoints);
    free(result->base.message);
    result->breakpoints = NULL;
    result->num_breakpoints = 0;
}

void dap_set_data_breakpoints_result_free(DAPSetDataBreakpointsResult* result) {
    if (!result) return;
    for (size_t i = 0; i < result->num_breakpoints; i++) {
        free(result->breakpoints[i].data_id);
        free(result->breakpoints[i].condition);
        free(result->breakpoints[i].hit_condition);
        free(result->breakpoints[i].message);
    }
    free(result->breakpoints);
    free(result->base.message);
    result->breakpoints = NULL;
    result->num_breakpoints = 0;
}

int dap_client_console_enable(DAPClient* client, int terminal, bool enable)
{
    if (!client) return DAP_ERROR_INVALID_ARG;

    cJSON *args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "terminal", terminal);
    cJSON_AddBoolToObject(args, "enable", enable);

    char *response_body = NULL;
    int result = dap_client_send_request(client, DAP_CMD_CONSOLE_ENABLE, args, &response_body);
    cJSON_Delete(args);
    free(response_body);
    return result;
}

int dap_client_console_write(DAPClient* client, int terminal, const char* input, bool hex)
{
    if (!client || !input) return DAP_ERROR_INVALID_ARG;

    cJSON *args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "terminal", terminal);
    cJSON_AddStringToObject(args, "input", input);
    if (hex) {
        cJSON_AddBoolToObject(args, "hex", true);
    }

    char *response_body = NULL;
    int result = dap_client_send_request(client, DAP_CMD_CONSOLE_WRITE, args, &response_body);
    cJSON_Delete(args);
    free(response_body);
    return result;
}

int dap_client_symbol_list(DAPClient* client, const char* filter,
                           int symbol_type, int offset, int count,
                           char** response_body)
{
    if (!client) return DAP_ERROR_INVALID_ARG;

    cJSON* args = cJSON_CreateObject();
    if (filter) cJSON_AddStringToObject(args, "filter", filter);
    if (symbol_type > 0) cJSON_AddNumberToObject(args, "symbolType", symbol_type);
    if (offset > 0) cJSON_AddNumberToObject(args, "offset", offset);
    if (count > 0) cJSON_AddNumberToObject(args, "count", count);

    int result = dap_client_send_request(client, DAP_CMD_SYMBOL_LIST, args, response_body);
    cJSON_Delete(args);
    return result;
}
