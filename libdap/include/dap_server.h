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


// Debug logging macro
#define DAP_SERVER_DEBUG_LOG(...)                                   \
    do                                                              \
    {                                                               \
        fprintf(stderr, "[DAP SERVER %s:%d] ", __func__, __LINE__); \
        fprintf(stderr, __VA_ARGS__);                               \
        fprintf(stderr, "\n");                                      \
        fflush(stderr);                                             \
    } while (0)

    

// Define MAX_BREAKPOINTS if not already defined
#ifndef MAX_BREAKPOINTS
#define MAX_BREAKPOINTS 100 // Maximum number of breakpoints
#endif

#include <dap_protocol.h>
#include <dap_transport.h>


// Forward declaration of DAPServer
typedef struct DAPServer DAPServer;

/**
 * @struct DAPClientCapabilities
 * @brief Capabilities reported by the client during initialization
 * @details These properties are sent from the client to the debug adapter in the 'initialize' request
 */
typedef struct DAPClientCapabilities
{
    /**
     * @brief The ID of the client using this adapter
     * @details Optional field, e.g., "vscode"
     */
    char *clientID;

    /**
     * @brief The human-readable name of the client using this adapter
     * @details Optional field, e.g., "Visual Studio Code"
     */
    char *clientName;

    /**
     * @brief The ID of the debug adapter
     * @details Required field, e.g., "ND-100 Assembly"
     */
    char *adapterID;

    /**
     * @brief The ISO-639 locale of the client using this adapter
     * @details E.g., en-US or de-CH
     */
    char *locale;

    /**
     * @brief Whether line numbers are 1-based (true) or 0-based (false)
     * @details Default is true (1-based)
     */
    bool linesStartAt1;

    /**
     * @brief Whether column numbers are 1-based (true) or 0-based (false)
     * @details Default is true (1-based)
     */
    bool columnsStartAt1;

    /**
     * @brief Format in which paths are specified
     * @details Values: 'path' (native format, default), 'uri', etc.
     */
    char *pathFormat;

    /**
     * @brief Whether client supports the 'type' attribute for variables
     */
    bool supportsVariableType;

    /**
     * @brief Whether client supports the paging of variables
     */
    bool supportsVariablePaging;

    /**
     * @brief Whether client supports the runInTerminal request
     */
    bool supportsRunInTerminalRequest;

    /**
     * @brief Whether client supports memory references
     */
    bool supportsMemoryReferences;

    /**
     * @brief Whether client supports progress reporting
     */
    bool supportsProgressReporting;

    /**
     * @brief Whether client supports the invalidated event
     */
    bool supportsInvalidatedEvent;

    /**
     * @brief Whether client supports the memory event
     */
    bool supportsMemoryEvent;

    /**
     * @brief Whether client supports the argsCanBeInterpretedByShell attribute on runInTerminal
     */
    bool supportsArgsCanBeInterpretedByShell;

    /**
     * @brief Whether client supports the startDebugging request
     */
    bool supportsStartDebuggingRequest;

    /**
     * @brief Whether client will interpret ANSI escape sequences in output
     */
    bool supportsANSIStyling;
} DAPClientCapabilities;

/**
 * @struct DAPResponse
 * @brief Response structure for DAP commands
 */
typedef struct
{
    bool success;        /**< Whether the command succeeded */
    char *data;          /**< Response data (JSON string) */
    size_t data_size;    /**< Size of response data */
    char *error_message; /**< Error message if failed, NULL if succeeded */
} DAPResponse;

// Source line mapping structure
typedef struct
{
    const char *file_path;  /**< Source file path */
    int original_line;      /**< Original line number */
    int dap_line;           /**< DAP line number */
    uint32_t address;       /**< Memory address */
} SourceLineMap;

/**
 * @struct Register
 * @brief Structure representing a CPU register
 */
typedef struct 
{
    const char* name;   /**< Register name */
    uint16_t value;     /**< Register value */
    const char* type;   /**< Register type (integer, bitmask, octal, etc.) */
    bool has_nested;    /**< Whether this register has nested variables (like status flags) */
    int nested_ref;     /**< Reference number for nested variables */
} Register;

/**
 * @struct StatusFlag
 * @brief Structure representing a status flag bit
 */
typedef struct 
{
    const char* name;   /**< Flag name */
    bool value;         /**< Flag value (true/false) */
    const char* type;   /**< Flag type */
} StatusFlag;

/**
 * @struct DAPServerConfig
 * @brief Configuration for the DAP server
 */
typedef struct
{
    const char *program_path;                 /**< Program path */
    DAPTransportConfig transport;             /**< Transport configuration */
} DAPServerConfig;

/**
 * @struct DAPCommandHandler
 * @brief Command handler function type
 */
typedef int (*DAPCommandHandler)(DAPServer *server, cJSON *args, DAPResponse *resp);

/**
 * @struct DAPServer
 * @brief DAP server context structure
 */
struct DAPServer
{
    DAPServerConfig config;  /**< Server configuration */
    DAPTransport *transport; /**< Transport instance */
    bool is_running;         /**< Whether server is running */
    bool is_initialized;     /**< Whether server is initialized */
    bool attached;           /**< Whether debugger is attached to target */
    bool paused;             /**< Whether execution is currently paused */

    int sequence;          /**< Current sequence number */
    int current_thread_id; /**< Current thread ID for execution control */
    int current_line;      /**< Current source line */
    int current_column;    /**< Current source column */
    int current_pc;        /**< Current program counter */
    
    char *program_path;

    const DAPSource *current_source;

    int breakpoint_count;
    DAPBreakpoint *breakpoints;

    // Line mapping fields
    SourceLineMap *line_maps;
    int line_map_count;
    int line_map_capacity;

    // Command handler array
    DAPCommandHandler command_handlers[DAP_CMD_MAX]; /**< Array of command handlers */
    
    ///Steps to the next machine instruction. This is useful for assembly debugging, 
    ///but we need to be careful with the order of breakpoint evaluation.
    bool step_to_next_instruction;

    // Stepping functions
    int (*step_cpu)(struct DAPServer *server);               /**< Step one CPU instruction */
    int (*step_cpu_line)(struct DAPServer *server);          /**< Step to next source line */
    int (*step_cpu_statement)(struct DAPServer *server);     /**< Step to next statement */

    // Client capabilities
    DAPClientCapabilities client_capabilities; /**< Capabilities reported by the client */
};

/**
 * @brief Create a new DAP server
 * @param config Server configuration
 * @return Server instance, or NULL on failure
 */
DAPServer *dap_server_create(const DAPServerConfig *config);

/**
 * @brief Initialize a DAP server
 * @param server Server instance
 * @param config Server configuration
 * @return 0 on success, non-zero on failure
 */
int dap_server_init(DAPServer *server, const DAPServerConfig *config);

/**
 * @brief Clean up resources used by a DAP server
 * @param server Server instance
 */
void dap_server_cleanup(DAPServer *server);

/**
 * @brief Free the DAP server
 * @param server Server instance
 */
void dap_server_free(DAPServer *server);

/**
 * @brief Start the DAP server
 * @param server Server instance
 * @return 0 on success, non-zero on failure
 */
int dap_server_start(DAPServer *server);

/**
 * @brief Stop the DAP server
 * @param server Server instance
 * @return 0 on success, non-zero on failure
 */
int dap_server_stop(DAPServer *server);

/**
 * @brief Handle an incoming DAP request string
 * @param server Server instance
 * @param request JSON request string
 * @return 0 on success, non-zero on failure
 */
int dap_server_handle_request(DAPServer *server, const char *request);

/**
 * @brief Process a message
 * @param server Server instance
 * @param message Message to process
 * @return 0 on success, non-zero on failure
 */
int dap_server_process_message(DAPServer *server, const char *message);

/**
 * @brief Handle a specific DAP command
 *
 * @param server Server instance
 * @param command Command type to handle
 * @param args_str Arguments for the command as JSON string, or NULL if json_args is provided
 * @param json_args Arguments for the command as cJSON object, or NULL if args_str is provided
 * @param response Response structure to fill
 * @return int 0 on success, non-zero on failure
 */
int dap_server_handle_command(DAPServer *server, DAPCommandType command,
                             const char *args_str, cJSON *json_args, DAPResponse *response);

/**
 * @brief Register a new command handler
 * @param server Server instance
 * @param command_id Command ID
 * @param handler Handler function
 * @return 0 on success, non-zero on failure
 */
int dap_server_register_command(DAPServer *server, int command_id, DAPCommandHandler handler);

/**
 * @brief Send a response to a client request
 * 
 * This is the primary function for sending standard DAP responses back to the client.
 * It constructs a properly formatted response message with all required DAP fields.
 * 
 * @param server Server instance
 * @param command Command type (must match the request being responded to)
 * @param sequence Sequence number (must match the request being responded to)
 * @param success Whether the request was successfully processed
 * @param body JSON object containing the response body (takes ownership and will free it)
 * @return 0 on success, non-zero on failure
 * 
 * @note This function takes ownership of the body cJSON object and will free it.
 *       Callers should not access or free the body after calling this function.
 */
int dap_server_send_response(DAPServer *server, DAPCommandType command,
                             int sequence, bool success, cJSON *body);

/**
 * @brief Send a response using the DAPResponse structure
 * 
 * Alternative response sender that uses the DAPResponse struct rather than individual parameters.
 * Useful for command handlers that prepare responses in the DAPResponse format.
 * 
 * @param server Server instance
 * @param response Response data structure containing success status, data (as JSON string), and error message
 * @return 0 on success, non-zero on failure
 * 
 * @note This function parses the response->data string into a cJSON object internally
 *       and manages its lifecycle, so callers only need to free the response struct's fields.
 */
int dap_server_send_response_struct(DAPServer *server, const DAPResponse *response);

/**
 * @brief Send an event to the client
 * 
 * Creates and sends a DAP event with the specified type and body.
 * Events are asynchronous notifications sent from the debug adapter to the client.
 * This is the preferred method for sending events (uses string-based event types per DAP spec).
 * 
 * @param server Server instance
 * @param event_type Event type as a string (e.g., "initialized", "stopped", "output")
 * @param body Event body as a JSON object (duplicated internally, original not modified)
 * @return 0 on success, non-zero on failure
 * 
 * @note This function duplicates the body object internally, so the caller retains
 *       ownership of the original body and is responsible for freeing it.
 */
int dap_server_send_event(DAPServer *server, const char *event_type, cJSON *body);

/**
 * @brief Send an event using enum type (deprecated)
 * 
 * Legacy function that uses enum-based event types instead of strings.
 * Maintained for backward compatibility with older code.
 * 
 * @param server Server instance
 * @param event_type Event type as an enum value
 * @param body Event body as a JSON object (duplicated internally)
 * @return 0 on success, non-zero on failure
 * 
 * @deprecated Use dap_server_send_event() instead, which follows the DAP specification
 *             by using string-based event types.
 * 
 * @note This function duplicates the body internally, caller retains ownership
 *       of the original body and must free it if necessary.
 */
int dap_server_send_event_enum(DAPServer *server, DAPEventType event_type, cJSON *body);

/**
 * @brief Send an output event to display console text
 * 
 * Convenience function to send a formatted output event to the client.
 * Used for displaying text in the debug console (stdout, stderr, telemetry, etc.).
 * 
 * @param server Server instance
 * @param category Output category ("console", "stdout", "stderr", or "telemetry")
 * @param output The text content to display
 * @return 0 on success, non-zero on failure
 * 
 * @note This function creates an appropriate JSON body internally with the
 *       category and output text, then uses dap_server_send_event() to send it.
 * 
 * @todo Function is currently declared but not implemented in the codebase.
 */
int dap_server_send_output_event(DAPServer *server, const char *category, const char *output);

/**
 * @brief Send a stopped event to indicate execution has paused
 * 
 * Convenience function to notify the client that execution has stopped/paused.
 * This is one of the most important events in DAP as it triggers UI updates in the client.
 * 
 * @param server Server instance
 * @param reason Reason for stopping ("step", "breakpoint", "exception", "pause", "entry", etc.)
 * @param description Human-readable description of why execution stopped
 * @return 0 on success, non-zero on failure
 * 
 * @note This creates a properly formatted "stopped" event with thread information
 *       and uses dap_server_send_event() to send it to the client.
 * 
 * @todo Function is currently declared but not implemented in the codebase.
 *       Used directly in launch_wrapper but could be extracted to this utility function.
 */
int dap_server_send_stopped_event(DAPServer *server, const char *reason, const char *description);

/**
 * @brief Add a line mapping entry
 * @param server Server instance
 * @param original_line Original line number
 * @param dap_line DAP line number
 * @return 0 on success, non-zero on failure
 */
int dap_server_add_line_mapping(DAPServer *server, int original_line, int dap_line);

/**
 * @brief Convert a program line number to a DAP line number
 * @param server Server instance
 * @param line Program line number
 * @return Corresponding DAP line number, or original line if no mapping found
 */
int dap_server_program_to_dap_line(DAPServer *server, int line);

/**
 * @brief Convert a DAP line number to a program line number
 * @param server Server instance
 * @param line DAP line number
 * @return Corresponding program line number, or original line if no mapping found
 */
int dap_server_dap_to_program_line(DAPServer *server, int line);

/**
 * @brief Add a breakpoint
 * @param server Server instance
 * @param bp Breakpoint to add
 * @return 0 on success, non-zero on failure
 */
int dap_server_add_breakpoint(DAPServer *server, const DAPBreakpoint *bp);

/**
 * @brief Clear all breakpoints
 * @param server Server instance
 */
void dap_server_clear_breakpoints(DAPServer *server);

/**
 * @brief Helper function for initializing command handlers
 * @param server Server instance
 */
void initialize_command_handlers(DAPServer *server);

/**
 * @brief Helper function for cleaning up breakpoints
 * @param server Server instance
 */
void cleanup_breakpoints(DAPServer *server);

/**
 * @brief Helper function for cleaning up line maps
 * @param server Server instance
 */
void cleanup_line_maps(DAPServer *server);

/**
 * @brief Run the main server loop
 * @param server Server instance
 * @return 0 on success, non-zero on failure
 */
int dap_server_run(DAPServer *server);

/**
 * @brief Get a source line for a memory address
 * @param server Server instance
 * @param address Memory address
 * @return The line number or -1 if not found
 */
int get_line_for_address(DAPServer *server, uint32_t address);

/**
 * @brief Add a line mapping with file and address information
 * @param server Server instance
 * @param file_path Source file path
 * @param line Line number
 * @param address Memory address
 */
void add_line_map(DAPServer *server, const char *file_path, int line, uint32_t address);

#endif // ND100X_DAP_SERVER_H