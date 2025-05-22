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
 * @file dap_protocol.c
 * @brief Protocol implementation for the DAP library
 */

#include "dap_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include "dap_error.h"
#include <cjson/cJSON.h>

/**
 * @brief Command string table
 */
static const char* command_strings[] = {
    "initialize",
    "launch",
    "attach",
    "disconnect",
    "terminate",
    "restart",
    "setBreakpoints",
    "clearBreakpoints",
    "setFunctionBreakpoints",
    "setExceptionBreakpoints",
    "continue",
    "next",
    "stepIn",
    "stepOut",
    "pause",
    "stackTrace",
    "scopes",
    "variables",
    "setVariable",
    "source",
    "threads",
    "evaluate",
    "setExpression",
    "loadedSources",
    "readMemory",
    "writeMemory",
    "disassemble",
    "cancel",
    "configurationDone",
    "terminateThreads",
    "completions",
    "exceptionInfo",
    "dataBreakpointInfo",
    "setDataBreakpoints",
    "setInstructionBreakpoints",
    "modules",
    "stepBack",
    "reverseContinue",
    "restartFrame",
    "goto",
    "setExceptionFilters"
};

/**
 * @brief Event string table
 */
static const char* event_strings[] = {
    "initialized",
    "terminated",
    "exited",
    "stopped",
    "breakpoint",
    "output",
    "thread",
    "module",
    "process",
    "capabilities",
    "progressStart",
    "progressUpdate",
    "progressEnd",
    "invalidated",
    "memory",
    "runInTerminal"
};

/**
 * @brief Get the command string from a command type
 * 
 * @param type Command type
 * @return const char* Command string
 */
const char* get_command_string(DAPCommandType type) {
    size_t num_commands = sizeof(command_strings) / sizeof(command_strings[0]);
    if (type >= 0 && (size_t)type < num_commands) {
        return command_strings[type];
    }
    return NULL;
}

/**
 * @brief Get the event string from an event type
 * 
 * @param type Event type
 * @return const char* Event string
 */
const char* get_event_string(DAPEventType type) {
    size_t num_events = sizeof(event_strings) / sizeof(event_strings[0]);
    if (type >= 0 && (size_t)type < num_events) {
        return event_strings[type];
    }
    return NULL;
}

/**
 * @brief Parse a DAP header from a string
 * 
 * @param header_str String containing the header to parse
 * @return DAPHeader Parsed header structure
 */
DAPHeader dap_parse_header(const char* header_str) {
    DAPHeader header = {0, NULL};
    char* content_length_str = strstr(header_str, "Content-Length: ");
    if (content_length_str) {
        content_length_str += 16; // Skip "Content-Length: "
        header.content_length = atoi(content_length_str);
    }

    char* content_type_str = strstr(header_str, "Content-Type: ");
    if (content_type_str) {
        content_type_str += 14; // Skip "Content-Type: "
        char* end = strchr(content_type_str, '\r');
        if (end) {
            size_t len = end - content_type_str;
            header.content_type = malloc(len + 1);
            if (header.content_type) {
                strncpy(header.content_type, content_type_str, len);
                header.content_type[len] = '\0';
            }
        }
    }

    return header;
}

/**
 * @brief Find command type from string
 * 
 * @param command_str Command string
 * @return DAPCommandType Command type, or DAP_CMD_INVALID if not found
 */
DAPCommandType find_command_type(const char* command_str) {
    size_t num_commands = sizeof(command_strings) / sizeof(command_strings[0]);
    for (size_t i = 0; i < num_commands; i++) {
        if (strcmp(command_str, command_strings[i]) == 0) {
            return (DAPCommandType)i;
        }
    }
    
    return DAP_CMD_INVALID;
}

/**
 * @brief Find event type from string
 * 
 * @param event_str Event string
 * @return DAPEventType Event type, or DAP_EVENT_INVALID if not found
 */
static DAPEventType find_event_type(const char* event_str) {
    size_t num_events = sizeof(event_strings) / sizeof(event_strings[0]);
    for (size_t i = 0; i < num_events; i++) {
        if (strcmp(event_str, event_strings[i]) == 0) {
            return (DAPEventType)i;
        }
    }
    
    return DAP_EVENT_INVALID;
}

/**
 * @brief Parse a DAP message from JSON
 * 
 * @param json JSON string to parse
 * @param type_out Pointer to store message type
 * @param command_out Pointer to store command type
 * @param sequence_out Pointer to store sequence number
 * @param content_out Pointer to store content (caller must free this)
 * @return int 0 on success, -1 on error
 */
int dap_parse_message(const char* json, DAPMessageType* type_out, DAPCommandType* command_out,
                     int* sequence_out, cJSON** content_out) {
    if (!json || !type_out || !command_out || !sequence_out || !content_out) {
        return -1;
    }

    cJSON* root = cJSON_Parse(json);
    if (!root) {
        return -1;
    }

    // Parse message type
    cJSON* type_obj = cJSON_GetObjectItem(root, "type");
    if (!type_obj || !cJSON_IsString(type_obj)) {
        cJSON_Delete(root);
        return -1;
    }

    if (strcmp(type_obj->valuestring, "request") == 0) {
        *type_out = DAP_MESSAGE_REQUEST;
    } else if (strcmp(type_obj->valuestring, "response") == 0) {
        *type_out = DAP_MESSAGE_RESPONSE;
    } else if (strcmp(type_obj->valuestring, "event") == 0) {
        *type_out = DAP_MESSAGE_EVENT;
    } else {
        cJSON_Delete(root);
        return -1;
    }

    // Parse sequence number
    cJSON* seq_obj = cJSON_GetObjectItem(root, "seq");
    if (!seq_obj || !cJSON_IsNumber(seq_obj)) {
        cJSON_Delete(root);
        return -1;
    }
    *sequence_out = seq_obj->valueint;

    // Parse command/event type
    if (*type_out == DAP_MESSAGE_REQUEST || *type_out == DAP_MESSAGE_RESPONSE) {
        cJSON* cmd_obj = cJSON_GetObjectItem(root, "command");
        if (!cmd_obj || !cJSON_IsString(cmd_obj)) {
            cJSON_Delete(root);
            return -1;
        }
        *command_out = find_command_type(cmd_obj->valuestring);
    } else {
        cJSON* event_obj = cJSON_GetObjectItem(root, "event");
        if (!event_obj || !cJSON_IsString(event_obj)) {
            cJSON_Delete(root);
            return -1;
        }
        // Convert event type to command type
        DAPEventType event_type = find_event_type(event_obj->valuestring);
        *command_out = (DAPCommandType)event_type;
    }

    // Get content (arguments/body)
    if (*type_out == DAP_MESSAGE_REQUEST) {
        *content_out = cJSON_DetachItemFromObject(root, "arguments");
    } else if (*type_out == DAP_MESSAGE_RESPONSE) {
        *content_out = cJSON_DetachItemFromObject(root, "body");
    } else {
        *content_out = cJSON_DetachItemFromObject(root, "body");
    }

    cJSON_Delete(root);
    return 0;
}

/**
 * @brief Create a DAP response message
 * 
 * @param command Command type
 * @param sequence Sequence number from the request
 * @param request_seq Sequence number from the request
 * @param success Whether the command succeeded
 * @param body Response body (cJSON object)
 * @return cJSON* JSON object (caller must free)
 */
cJSON* dap_create_response(DAPCommandType command, int sequence, int request_seq, bool success, cJSON* body) {
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return NULL;
    }

    cJSON_AddStringToObject(root, "type", "response");    
    cJSON_AddNumberToObject(root, "seq", sequence);  // Add the request_seq field
    cJSON_AddNumberToObject(root, "request_seq", request_seq);  // Add the request_seq field
    cJSON_AddStringToObject(root, "command", get_command_string(command));
    cJSON_AddBoolToObject(root, "success", success);
    
    if (body) {
        cJSON_AddItemToObject(root, "body", body);
    }

    return root;
}

/**
 * @brief Create a DAP event message
 * 
 * @param event_type Event type
 * @param body Event body (cJSON object)
 * @return cJSON* JSON object (caller must free)
 * 
 * @note IMPORTANT: This function TAKES OWNERSHIP of the body parameter.
 *       The caller should not access or free the body after calling this function.
 *       The body will be freed when the returned event object is deleted.
 */
cJSON* dap_create_event(DAPEventType event_type, cJSON* body) {
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return NULL;
    }

    cJSON_AddStringToObject(root, "type", "event");
    cJSON_AddStringToObject(root, "event", get_event_string(event_type));
    
    if (body) {
        // Add the body directly to the event (taking ownership)
        cJSON_AddItemToObject(root, "body", body);
    }

    return root;
}

/**
 * @brief Create a DAP request message
 * 
 * @param command Command type
 * @param sequence Sequence number
 * @param args Request arguments (cJSON object)
 * @return cJSON* Request message, or NULL on error
 */
cJSON* dap_create_request(DAPCommandType command, int sequence, cJSON* args) {
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return NULL;
    }

    cJSON_AddStringToObject(root, "type", "request");
    cJSON_AddNumberToObject(root, "seq", sequence);
    cJSON_AddStringToObject(root, "command", get_command_string(command));
    
    if (args) {
        cJSON_AddItemToObject(root, "arguments", args);
    }

    return root;
} 