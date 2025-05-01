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
 * @file dap_server.h
 * @brief Server implementation for the DAP library
 */

#ifndef ND100X_DAP_SERVER_H
#define ND100X_DAP_SERVER_H

// Define MAX_BREAKPOINTS if not already defined
#ifndef MAX_BREAKPOINTS
#define MAX_BREAKPOINTS 100 // Maximum number of breakpoints supported
#endif

#include "dap_protocol.h"
#include "dap_message.h"
#include "dap_transport.h"

// Forward declarations
typedef struct DAPServer DAPServer;
typedef struct DAPServerConfig DAPServerConfig;

/**
 * @brief Response structure for DAP commands
 */
typedef struct
{
    bool success;        /**< Whether the command succeeded */
    char *data;          /**< Response data (JSON string) */
    size_t data_size;    /**< Size of response data */
    char *error_message; /**< Error message if failed, NULL if succeeded */
} DAPResponse;

// Line mapping structure
typedef struct
{
    const char *file_path;
    int line;
    uint32_t address;
} SourceLineMap;

/**
 * @brief DAP server configuration
 */
struct DAPServerConfig
{
    DAPTransportConfig transport; /**< Transport configuration */
    bool stop_at_entry;           /**< Whether to stop at program entry point */    
};

/**
 * @brief DAP server context
 */
struct DAPServer
{
    DAPServerConfig config;  /**< Server configuration */
    DAPTransport *transport; /**< Transport instance */
    bool is_running;         /**< Whether server is running */
    bool is_initialized;     /**< Whether server is initialized */

    int sequence;          /**< Current sequence number */
    int current_thread_id; /**< Current thread ID for execution control */

    const char *program_path;

    const DAPSource *current_source;

    int breakpoint_count;
    DAPBreakpoint *breakpoints;

    // Line mapping fields
    SourceLineMap *line_maps;
    int line_map_count;
    int line_map_capacity;

    // Not used ???

    int current_thread;
    int current_line;
    int current_column;

    bool running;
    bool attached;
    bool paused;
};

/**
 * @brief Create a new DAP server
 *
 * @param config Server configuration
 * @return DAPServer* New server instance, or NULL on error
 */
DAPServer *dap_server_create(const DAPServerConfig *config);

/**
 * @brief Initialize the DAP server
 *
 * @param server Server instance
 * @param config Server configuration
 * @return int 0 on success, -1 on error
 */
int dap_server_init(DAPServer *server, const DAPServerConfig *config);

/**
 * @brief Start the DAP server
 *
 * @param server Server instance
 * @return int 0 on success, -1 on error
 */
int dap_server_start(DAPServer *server);

/**
 * @brief Stop the DAP server
 *
 * @param server Server instance
 * @return int 0 on success, -1 on error
 */
int dap_server_stop(DAPServer *server);

/**
 * @brief Free the DAP server
 *
 * @param server Server instance
 */
void dap_server_free(DAPServer *server);

/**
 * @brief Process a DAP message
 *
 * @param server Server instance
 * @param message Message to process
 * @return int 0 on success, -1 on error
 */
int dap_server_process_message(DAPServer *server, const char *message);

/**
 * @brief Handle a DAP request
 *
 * @param server Server instance
 * @param command Command type
 * @param sequence Sequence number
 * @param content Request content (cJSON object)
 * @return int 0 on success, -1 on error
 */
int dap_server_handle_request(DAPServer *server, DAPCommandType command,
                              int sequence, cJSON *content);

/**
 * @brief Send a DAP response
 *
 * @param server Server instance
 * @param command Command type
 * @param sequence Sequence number
 * @param success Whether the request was successful
 * @param body Response body (cJSON object)
 * @return int 0 on success, -1 on error
 */
int dap_server_send_response(DAPServer *server, DAPCommandType command,
                             int sequence, bool success, cJSON *body);

/**
 * @brief Send an event to the client
 *
 * @param server Server instance
 * @param event_type Event type
 * @param body Event body (cJSON object)
 * @return int 0 on success, -1 on error
 */
int dap_server_send_event(DAPServer *server, DAPEventType event_type, cJSON *body);

/**
 * @brief Run the DAP server
 *
 * @param server Server instance
 * @return int 0 on success, -1 on error
 */
int dap_server_run(DAPServer *server);

/**
 * @brief Cleanup breakpoints
 *
 * @param debugger Server instance
 */
void cleanup_breakpoints(DAPServer *debugger);

/**
 * @brief Cleanup line maps
 *
 * @param dap_server Server instance
 */
void cleanup_line_maps(DAPServer *dap_server);

/**
 * @brief Handle a DAP command
 *
 * @param server Server instance
 * @param command Command type
 * @param args Command arguments
 * @param response Response structure
 * @return int 0 on success, -1 on error
 */
int dap_server_handle_command(DAPServer *server, DAPCommandType command, const char *args, DAPResponse *response);

#endif /* ND100X_DAP_SERVER_H */