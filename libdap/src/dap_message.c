/**
 * @file dap_message.c
 * @brief Message handling implementation for the DAP library
 */

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
 * @file dap_message.c
 * @brief Implementation of the Debug Adapter Protocol message handling
 * 
 */

#include "dap_message.h"
#include "dap_protocol.h"
#include "dap_error.h"
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Debug logging macro
#define DAP_MESSAGE_DEBUG_LOG(...) do { \
    fprintf(stderr, "[DAP Message %s:%d] ", __func__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
    fflush(stderr); \
} while(0)

bool dap_json_validate(const cJSON* json) {
    if (!json) {
        DAP_MESSAGE_DEBUG_LOG("Invalid JSON: NULL pointer");
        return false;
    }

    // Check for common issues
    if (json->type == cJSON_Invalid) {
        DAP_MESSAGE_DEBUG_LOG("Invalid JSON: Invalid type");
        return false;
    }

    // Check for circular references
    const cJSON* current = json;
    const cJSON* next = NULL;
    while (current) {
        next = current->next;
        if (next == json) {
            DAP_MESSAGE_DEBUG_LOG("Invalid JSON: Circular reference detected");
            return false;
        }
        current = next;
    }

    return true;
}

DAPMessage* dap_message_create_request(const char* command, int sequence, cJSON* arguments) {
    if (!command || !arguments) {
        DAP_MESSAGE_DEBUG_LOG("Invalid arguments");
        return NULL;
    }

    DAPMessage* msg = (DAPMessage*)malloc(sizeof(DAPMessage));
    if (!msg) {
        DAP_MESSAGE_DEBUG_LOG("Failed to allocate memory for message");
        return NULL;
    }

    msg->type = DAP_MESSAGE_REQUEST;
    msg->sequence = sequence;
    msg->content.request.command = strdup(command);
    msg->content.request.arguments = cJSON_Duplicate(arguments, true);
    
    if (!msg->content.request.command || !msg->content.request.arguments) {
        DAP_MESSAGE_DEBUG_LOG("Failed to duplicate command or arguments");
        free(msg->content.request.command);
        cJSON_Delete(msg->content.request.arguments);
        free(msg);
        return NULL;
    }

    return msg;
}

DAPMessage* dap_message_create_response(const char* command, int sequence, int request_sequence, bool success, cJSON* body) {
    if (!command) {
        DAP_MESSAGE_DEBUG_LOG("Invalid arguments");
        return NULL;
    }

    DAPMessage* msg = (DAPMessage*)malloc(sizeof(DAPMessage));
    if (!msg) {
        DAP_MESSAGE_DEBUG_LOG("Failed to allocate memory for message");
        return NULL;
    }

    msg->type = DAP_MESSAGE_RESPONSE;
    msg->sequence = sequence;
    msg->content.response.request_sequence = request_sequence;
    msg->content.response.command = strdup(command);
    msg->content.response.success = success;
    msg->content.response.body = body ? cJSON_Duplicate(body, true) : NULL;
    
    if (!msg->content.response.command || (body && !msg->content.response.body)) {
        DAP_MESSAGE_DEBUG_LOG("Failed to duplicate command or body");
        free(msg->content.response.command);
        cJSON_Delete(msg->content.response.body);
        free(msg);
        return NULL;
    }

    return msg;
}

DAPMessage* dap_message_create_event(const char* event, int sequence, cJSON* body) {
    if (!event) {
        DAP_MESSAGE_DEBUG_LOG("Invalid arguments");
        return NULL;
    }

    DAPMessage* msg = (DAPMessage*)malloc(sizeof(DAPMessage));
    if (!msg) {
        DAP_MESSAGE_DEBUG_LOG("Failed to allocate memory for message");
        return NULL;
    }

    msg->type = DAP_MESSAGE_EVENT;
    msg->sequence = sequence;
    msg->content.event.event = strdup(event);
    msg->content.event.body = body ? cJSON_Duplicate(body, true) : NULL;
    
    if (!msg->content.event.event || (body && !msg->content.event.body)) {
        DAP_MESSAGE_DEBUG_LOG("Failed to duplicate event or body");
        free(msg->content.event.event);
        cJSON_Delete(msg->content.event.body);
        free(msg);
        return NULL;
    }

    return msg;
}

void dap_message_free(DAPMessage* msg) {
    if (!msg) return;
    
    switch (msg->type) {
        case DAP_MESSAGE_REQUEST:
            free(msg->content.request.command);
            cJSON_Delete(msg->content.request.arguments);
            break;
        case DAP_MESSAGE_RESPONSE:
            free(msg->content.response.command);
            cJSON_Delete(msg->content.response.body);
            break;
        case DAP_MESSAGE_EVENT:
            free(msg->content.event.event);
            cJSON_Delete(msg->content.event.body);
            break;
    }
    free(msg);
}

char* dap_message_serialize(const DAPMessage* msg) {
    if (!msg) {
        DAP_MESSAGE_DEBUG_LOG("Invalid message");
        return NULL;
    }

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        DAP_MESSAGE_DEBUG_LOG("Failed to create root object");
        return NULL;
    }

    // Add message type
    const char* type_str = NULL;
    switch (msg->type) {
        case DAP_MESSAGE_REQUEST:
            type_str = "request";
            break;
        case DAP_MESSAGE_RESPONSE:
            type_str = "response";
            break;
        case DAP_MESSAGE_EVENT:
            type_str = "event";
            break;
        default:
            DAP_MESSAGE_DEBUG_LOG("Invalid message type");
            cJSON_Delete(root);
            return NULL;
    }
    cJSON_AddStringToObject(root, "type", type_str);

    // Add sequence number
    cJSON_AddNumberToObject(root, "seq", msg->sequence);

    // Add type-specific fields
    switch (msg->type) {
        case DAP_MESSAGE_REQUEST:
            cJSON_AddStringToObject(root, "command", msg->content.request.command);
            if (msg->content.request.arguments) {
                cJSON_AddItemToObject(root, "arguments", cJSON_Duplicate(msg->content.request.arguments, true));
            }
            break;
        case DAP_MESSAGE_RESPONSE:
            cJSON_AddNumberToObject(root, "request_seq", msg->content.response.request_sequence);
            cJSON_AddStringToObject(root, "command", msg->content.response.command);
            cJSON_AddBoolToObject(root, "success", msg->content.response.success);
            if (msg->content.response.body) {
                cJSON_AddItemToObject(root, "body", cJSON_Duplicate(msg->content.response.body, true));
            }
            break;
        case DAP_MESSAGE_EVENT:
            cJSON_AddStringToObject(root, "event", msg->content.event.event);
            if (msg->content.event.body) {
                cJSON_AddItemToObject(root, "body", cJSON_Duplicate(msg->content.event.body, true));
            }
            break;
    }

    char* json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}

DAPMessage* dap_message_parse(const char* json) {
    if (!json) {
        DAP_MESSAGE_DEBUG_LOG("Invalid JSON string");
        return NULL;
    }

    cJSON* root = cJSON_Parse(json);
    if (!root || !dap_json_validate(root)) {
        DAP_MESSAGE_DEBUG_LOG("Failed to parse JSON");
        return NULL;
    }

    DAPMessage* msg = (DAPMessage*)malloc(sizeof(DAPMessage));
    if (!msg) {
        DAP_MESSAGE_DEBUG_LOG("Failed to allocate memory for message");
        cJSON_Delete(root);
        return NULL;
    }

    // Parse message type
    cJSON* type = cJSON_GetObjectItem(root, "type");
    if (!type || !cJSON_IsString(type)) {
        DAP_MESSAGE_DEBUG_LOG("Invalid or missing message type");
        cJSON_Delete(root);
        free(msg);
        return NULL;
    }

    if (strcmp(type->valuestring, "request") == 0) {
        msg->type = DAP_MESSAGE_REQUEST;
    } else if (strcmp(type->valuestring, "response") == 0) {
        msg->type = DAP_MESSAGE_RESPONSE;
    } else if (strcmp(type->valuestring, "event") == 0) {
        msg->type = DAP_MESSAGE_EVENT;
    } else {
        DAP_MESSAGE_DEBUG_LOG("Unknown message type: %s", type->valuestring);
        cJSON_Delete(root);
        free(msg);
        return NULL;
    }

    // Parse sequence number
    cJSON* seq = cJSON_GetObjectItem(root, "seq");
    if (!seq || !cJSON_IsNumber(seq)) {
        DAP_MESSAGE_DEBUG_LOG("Invalid or missing sequence number");
        cJSON_Delete(root);
        free(msg);
        return NULL;
    }
    msg->sequence = seq->valueint;

    // Parse type-specific fields
    switch (msg->type) {
        case DAP_MESSAGE_REQUEST: {
            cJSON* command = cJSON_GetObjectItem(root, "command");
            if (!command || !cJSON_IsString(command)) {
                DAP_MESSAGE_DEBUG_LOG("Invalid or missing command");
                cJSON_Delete(root);
                free(msg);
                return NULL;
            }
            msg->content.request.command = strdup(command->valuestring);
            msg->content.request.arguments = cJSON_DetachItemFromObject(root, "arguments");
            if (!msg->content.request.command) {
                DAP_MESSAGE_DEBUG_LOG("Failed to duplicate command");
                cJSON_Delete(root);
                free(msg);
                return NULL;
            }
            break;
        }
        case DAP_MESSAGE_RESPONSE: {
            cJSON* request_seq = cJSON_GetObjectItem(root, "request_seq");
            cJSON* command = cJSON_GetObjectItem(root, "command");
            cJSON* success = cJSON_GetObjectItem(root, "success");
            if (!request_seq || !cJSON_IsNumber(request_seq) ||
                !command || !cJSON_IsString(command) ||
                !success || !cJSON_IsBool(success)) {
                DAP_MESSAGE_DEBUG_LOG("Invalid or missing response fields");
                cJSON_Delete(root);
                free(msg);
                return NULL;
            }
            msg->content.response.request_sequence = request_seq->valueint;
            msg->content.response.command = strdup(command->valuestring);
            msg->content.response.success = cJSON_IsTrue(success);
            msg->content.response.body = cJSON_DetachItemFromObject(root, "body");
            if (!msg->content.response.command) {
                DAP_MESSAGE_DEBUG_LOG("Failed to duplicate command");
                cJSON_Delete(root);
                free(msg);
                return NULL;
            }
            break;
        }
        case DAP_MESSAGE_EVENT: {
            cJSON* event = cJSON_GetObjectItem(root, "event");
            if (!event || !cJSON_IsString(event)) {
                DAP_MESSAGE_DEBUG_LOG("Invalid or missing event");
                cJSON_Delete(root);
                free(msg);
                return NULL;
            }
            msg->content.event.event = strdup(event->valuestring);
            msg->content.event.body = cJSON_DetachItemFromObject(root, "body");
            if (!msg->content.event.event) {
                DAP_MESSAGE_DEBUG_LOG("Failed to duplicate event");
                cJSON_Delete(root);
                free(msg);
                return NULL;
            }
            break;
        }
    }

    cJSON_Delete(root);
    return msg;
} 