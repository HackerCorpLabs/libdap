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
 * @file dap_protocol.h
 * @brief Debug Adapter Protocol definitions
 */

#ifndef ND100X_DAP_PROTOCOL_H
#define ND100X_DAP_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <cjson/cJSON.h>
#include "dap_types.h"

/**
 * @brief DAP message types
 */
typedef enum {
    DAP_MESSAGE_REQUEST,
    DAP_MESSAGE_RESPONSE,
    DAP_MESSAGE_EVENT
} DAPMessageType;

/**
 * @brief DAP command types
 */
typedef enum {
    DAP_CMD_INVALID = -1,        ///< Invalid command type
    DAP_CMD_INITIALIZE,          ///< Initialize request
    DAP_CMD_LAUNCH,              ///< Launch request
    DAP_CMD_ATTACH,              ///< Attach request
    DAP_CMD_DISCONNECT,          ///< Disconnect request
    DAP_CMD_TERMINATE,           ///< Terminate request
    DAP_CMD_RESTART,             ///< Restart request
    DAP_CMD_SET_BREAKPOINTS,     ///< Set breakpoints request
    DAP_CMD_CLEAR_BREAKPOINTS,   ///< Clear breakpoints request
    DAP_CMD_SET_FUNCTION_BREAKPOINTS,  ///< Set function breakpoints request
    DAP_CMD_SET_EXCEPTION_BREAKPOINTS, ///< Set exception breakpoints request
    DAP_CMD_CONTINUE,            ///< Continue request
    DAP_CMD_NEXT,                ///< Next request
    DAP_CMD_STEP_IN,             ///< Step in request
    DAP_CMD_STEP_OUT,            ///< Step out request
    DAP_CMD_PAUSE,               ///< Pause request
    DAP_CMD_STACK_TRACE,         ///< Stack trace request
    DAP_CMD_SCOPES,              ///< Scopes request
    DAP_CMD_VARIABLES,           ///< Variables request
    DAP_CMD_SET_VARIABLE,        ///< Set variable request
    DAP_CMD_SOURCE,              ///< Source request
    DAP_CMD_THREADS,             ///< Threads request
    DAP_CMD_EVALUATE,            ///< Evaluate request
    DAP_CMD_SET_EXPRESSION,      ///< Set expression request
    DAP_CMD_LOADED_SOURCES,      ///< Loaded sources request
    DAP_CMD_READ_MEMORY,         ///< Read memory request
    DAP_CMD_WRITE_MEMORY,        ///< Write memory request
    DAP_CMD_DISASSEMBLE,         ///< Disassemble request
    DAP_CMD_CANCEL,              ///< Cancel request
    DAP_CMD_CONFIGURATION_DONE,  ///< Configuration done request
    DAP_CMD_TERMINATE_THREADS,   ///< Terminate threads request
    DAP_CMD_COMPLETIONS,         ///< Completions request
    DAP_CMD_EXCEPTION_INFO,      ///< Exception info request
    DAP_CMD_DATA_BREAKPOINT_INFO,///< Data breakpoint info request
    DAP_CMD_SET_DATA_BREAKPOINTS,///< Set data breakpoints request
    DAP_CMD_SET_INSTRUCTION_BREAKPOINTS, ///< Set instruction breakpoints request
    DAP_CMD_MODULES,             ///< Modules request
    DAP_CMD_STEP_BACK,           ///< Step back request
    DAP_CMD_REVERSE_CONTINUE,    ///< Reverse continue request
    DAP_CMD_RESTART_FRAME,       ///< Restart frame request
    DAP_CMD_GOTO,                ///< Goto request
    DAP_CMD_SET_EXCEPTION_FILTERS, ///< Set exception filters request    
    //---
    DAP_WAIT_FOR_DEBUGGER,         ///Always called before any other DAP command to wait for the debugger to be ready for access to CPU registers and memory
    DAP_RELEASE_DEBUGGER,          ///Always called after all DAP commands to release the debugger
    //--
    DAP_CMD_MAX         
} DAPCommandType;

/**
 * @brief DAP event types
 */
typedef enum {
    DAP_EVENT_INVALID = -1,      ///< Invalid event type
    DAP_EVENT_INITIALIZED,       ///< Initialized event
    DAP_EVENT_TERMINATED,        ///< Terminated event
    DAP_EVENT_EXITED,            ///< Exited event
    DAP_EVENT_STOPPED,           ///< Stopped event
    DAP_EVENT_BREAKPOINT,        ///< Breakpoint event
    DAP_EVENT_OUTPUT,            ///< Output event
    DAP_EVENT_THREAD,            ///< Thread event
    DAP_EVENT_MODULE,            ///< Module event
    DAP_EVENT_PROCESS,           ///< Process event
    DAP_EVENT_CAPABILITIES,      ///< Capabilities event
    DAP_EVENT_PROGRESS_START,    ///< Progress start event
    DAP_EVENT_PROGRESS_UPDATE,   ///< Progress update event
    DAP_EVENT_PROGRESS_END,      ///< Progress end event
    DAP_EVENT_INVALIDATED,       ///< Invalidated event
    DAP_EVENT_MEMORY,            ///< Memory event
    DAP_EVENT_RUN_IN_TERMINAL    ///< Run in terminal event
} DAPEventType;

/**
 * @brief DAP message header
 */
typedef struct {
    int content_length;
    char* content_type;
} DAPHeader;

/**
 * @brief Get the command string from a command type
 * 
 * @param type Command type
 * @return const char* Command string
 */
const char* get_command_string(DAPCommandType type);

/**
 * @brief Get the event string from an event type
 * 
 * @param type Event type
 * @return const char* Event string
 */
const char* get_event_string(DAPEventType type);

/**
 * @brief Parse a DAP header from a string
 * 
 * @param header_str String containing the header to parse
 * @return DAPHeader Parsed header structure
 */
DAPHeader dap_parse_header(const char* header_str);

/**
 * @brief Parse a DAP message body from a JSON string
 * 
 * @param json JSON string to parse
 * @param type Pointer to store the message type
 * @param command Pointer to store the command type
 * @param sequence Pointer to store the sequence number
 * @param content Pointer to store the content (caller must free this)
 * @return int 0 on success, -1 on error
 */
int dap_parse_message(const char* json, DAPMessageType* type, DAPCommandType* command, 
                      int* sequence, cJSON** content);

/**
 * @brief Create a DAP request message
 * 
 * @param command Command type
 * @param sequence Sequence number
 * @param args Request arguments (cJSON object)
 * @return cJSON* Request message, or NULL on error
 */
cJSON* dap_create_request(DAPCommandType command, int sequence, cJSON* args);

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
cJSON* dap_create_response(DAPCommandType command, int sequence, int request_seq, bool success, cJSON* body);

/**
 * @brief Create a DAP event message
 * 
 * @param event_type Event type
 * @param body Event body (cJSON object) - this function takes ownership of the body
 * @return cJSON* JSON object (caller must free)
 */
cJSON* dap_create_event(DAPEventType event_type, cJSON* body);

/**
 * @brief Find command type from string
 * 
 * @param command_str Command string
 * @return DAPCommandType Command type, or DAP_CMD_INVALID if not found
 */
DAPCommandType find_command_type(const char* command_str);

#endif /* ND100X_DAP_PROTOCOL_H */ 