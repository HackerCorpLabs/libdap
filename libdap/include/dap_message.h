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
 * @file dap_message.h
 * @brief Debug Adapter Protocol message handling definitions
 * 
 */

#ifndef ND100X_DAP_MESSAGE_H
#define ND100X_DAP_MESSAGE_H

#include "dap_protocol.h"
#include "dap_types.h"
#include <cjson/cJSON.h>

/**
 * @brief DAP message structure
 */
typedef struct {
    DAPMessageType type;     /**< Message type */
    int sequence;            /**< Sequence number */
    union {
        struct {
            char* command;           /**< Command name (owned by the structure) */
            cJSON* arguments;        /**< Request arguments (owned by the structure) */
        } request;
        struct {
            int request_sequence;    /**< Sequence number of the request */
            char* command;           /**< Command name (owned by the structure) */
            bool success;            /**< Whether the request succeeded */
            cJSON* body;             /**< Response body (owned by the structure) */
        } response;
        struct {
            char* event;             /**< Event name (owned by the structure) */
            cJSON* body;             /**< Event body (owned by the structure) */
        } event;
    } content;               /**< Message content based on type */
} DAPMessage;

/**
 * @brief Create a new DAP request message
 * 
 * @param command Command name (will be copied)
 * @param sequence Sequence number
 * @param arguments Request arguments (ownership transferred to the message)
 * @return DAPMessage* New message instance, or NULL on error
 */
DAPMessage* dap_message_create_request(const char* command, int sequence, cJSON* arguments);

/**
 * @brief Create a new DAP response message
 * 
 * @param command Command name (will be copied)
 * @param sequence Sequence number
 * @param request_sequence Sequence number of the request
 * @param success Whether the request succeeded
 * @param body Response body (ownership transferred to the message)
 * @return DAPMessage* New message instance, or NULL on error
 */
DAPMessage* dap_message_create_response(const char* command, int sequence, int request_sequence, bool success, cJSON* body);

/**
 * @brief Create a new DAP event message
 * 
 * @param event Event name (will be copied)
 * @param sequence Sequence number
 * @param body Event body (ownership transferred to the message)
 * @return DAPMessage* New message instance, or NULL on error
 */
DAPMessage* dap_message_create_event(const char* event, int sequence, cJSON* body);

/**
 * @brief Free a DAP message
 * 
 * @param message Message to free
 * 
 * @note This function will free all memory owned by the message, including:
 *       - The command/event string
 *       - The arguments/body cJSON object
 *       - The message structure itself
 */
void dap_message_free(DAPMessage* message);

/**
 * @brief Serialize a DAP message to JSON
 * 
 * @param message Message to serialize (ownership remains with caller)
 * @return char* JSON string (caller must free)
 */
char* dap_message_serialize(const DAPMessage* message);

/**
 * @brief Parse a JSON string into a DAP message
 * 
 * @param json JSON string to parse (ownership remains with caller)
 * @return DAPMessage* Parsed message (caller must free with dap_message_free())
 */
DAPMessage* dap_message_parse(const char* json);

#endif /* ND100X_DAP_MESSAGE_H */ 