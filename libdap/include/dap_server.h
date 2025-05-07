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
    int request_seq;     /**< Sequence number of the original request */
    int sequence;        /**< Sequence number of the response */
} DAPResponse;


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
 * @enum StepGranularity
 * @brief Granularity options for stepping commands (per DAP spec)
 */
typedef enum {
    /// @brief Step by statement (default) - Stop at next source statement (PC at different line or new symbol)
    DAP_STEP_GRANULARITY_STATEMENT,     
    /// @brief Step by a single instruction - Stop after next machine instruction (PC += 1 instruction))
    DAP_STEP_GRANULARITY_INSTRUCTION, 
    /// @brief Step by source line - Stop at next different source line
    DAP_STEP_GRANULARITY_LINE,        
} StepGranularity;

/**
 * @struct DAPCommandHandler
 * @brief Command handler function type
 */
typedef int (*DAPCommandHandler)(DAPServer *server, cJSON *args, DAPResponse *resp);

/**
 * @struct StepCommandContext
 * @brief Context for step commands (stepIn, stepOut, next)
 */
typedef struct {
    int thread_id;               /**< Thread ID to step */
    bool single_thread;          /**< Whether to step only the specified thread */
    StepGranularity granularity; /**< Step granularity (instruction, line, statement) */
    int target_id;               /**< Target ID (used for stepIn) */
} StepCommandContext;

/**
 * @struct BreakpointCommandContext
 * @brief Context for breakpoint commands
 */
typedef struct {
    const char* source_path;           /**< Source file path */
    const char* source_name;           /**< Source file name */
    bool source_modified;              /**< Whether the source file has been modified */
    const DAPBreakpoint* breakpoints;  /**< Array of breakpoint objects */
    int breakpoint_count;              /**< Number of breakpoints */
    //int* lines;                        /**< Legacy: Simple line array */
    //bool use_lines_array;              /**< Whether to use simplified lines array */
} BreakpointCommandContext;

/**
 * @struct ExceptionBreakpointCommandContext
 * @brief Context for exception breakpoint commands
 */
typedef struct {
    const char** filters;        /**< Array of exception filter IDs */
    size_t filter_count;         /**< Number of filters */
    const char** conditions;     /**< Array of filter conditions */
    size_t condition_count;      /**< Number of conditions */
} ExceptionBreakpointCommandContext;

/**
 * @struct StackTraceFormat
 * @brief Format options for stack trace requests
 */
typedef struct {
    bool parameters;          /**< Include parameter information */
    bool parameter_types;     /**< Include parameter type information */
    bool parameter_names;     /**< Include parameter name information */
    bool parameter_values;    /**< Include parameter value information */
    bool line;                /**< Include line information */
    bool module;              /**< Include module information */
    bool include_all;         /**< Include all possible information */
} StackTraceFormat;

/**
 * @struct StackTraceCommandContext
 * @brief Context for stack trace command
 */
typedef struct {
    int start_frame;             /**< Starting frame index */
    int levels;                  /**< Number of frames to retrieve */
    StackTraceFormat format;     /**< Format options for the response */
    
    // Results
    DAPStackFrame *frames;       /**< Stack frames array to be filled by callback */
    int frame_count;             /**< Number of frames in the array */
    int total_frames;            /**< Total number of frames available */
} StackTraceCommandContext;

/**
 * @struct DAPStackFrameResponse
 * @brief Response structure for stack frames that callbacks can fill
 */
typedef struct {
    int id;                 /**< Frame ID (typically 0 for the top frame) */
    char* name;             /**< Name of the frame (e.g., function name) */
    int line;               /**< Source line number */
    int column;             /**< Source column number */
    char* source_path;      /**< Path to the source file */
    char* source_name;      /**< Name of the source file */
    bool valid;             /**< Whether this frame is valid/populated */
} DAPStackFrameResponse;

/**
 * @struct LaunchCommandContext
 * @brief Context structure for the DAP 'launch' request command
 * 
 * This structure holds all the parameters and state needed to process a launch request
 * according to the Debug Adapter Protocol specification.
 * 
 * The launch request is used to start debugging a program. The debug adapter first
 * configures everything for debugging the program and then starts it. Some debug
 * adapters support running the program without debugging (if noDebug is true).
 * 
 * Field Descriptions (from DAP Specification):
 * @param program_path Required. Path to the program to debug. This can be an absolute 
 *                    or relative path, and should point to the debuggee executable.
 * 
 * @param source_path Optional. Path to the main source file. Used for source mapping
 *                    and as the initial file shown in the debug UI.
 * 
 * @param map_path Optional. Path to debug symbol/mapping file if separate from executable.
 *                Used for source-level debugging and variable inspection.
 * 
 * @param working_directory Optional. Current working directory for the debuggee.
 *                         If not specified, the debugger's CWD is used.
 * 
 * @param no_debug Optional. If true, the program is launched without debugging.
 *                Allows running program at full speed with no debug features.
 * 
 * @param stop_at_entry Optional. If true, the debugger should stop at the entry point
 *                      of the program. Default is implementation-dependent.
 * 
 * @param args Optional. Command line arguments to pass to the program.
 *             Stored as an array of strings.
 * 
 * @param args_count Number of command line arguments in the args array.
 * 
 * @param launch_args Optional. Additional implementation-specific launch arguments.
 *                    Can be used for language/runtime specific options.
 */
typedef struct {
    const char* program_path;       /**< Path to the program to be debugged */
    const char* source_path;        /**< Path to the source file */
    const char* map_path;           /**< Path to the map file (for debugging symbols) */
    const char* working_directory;  /**< Working directory for the debuggee */
    bool no_debug;                  /**< Whether to run without debugging support */
    bool stop_at_entry;             /**< Whether to stop at program entry point */
    char** args;                    /**< Command line arguments array */
    int args_count;                 /**< Number of command line arguments */
    void* launch_args;              /**< Additional language-specific launch args */
} LaunchCommandContext;

/**
 * @struct RestartCommandContext
 * @brief Context for restart command
 */
typedef struct {
    bool no_debug;                  /**< Whether to restart without debugging support */
    void* restart_args;             /**< Additional language-specific restart args */
} RestartCommandContext;

/**
 * @struct DisconnectCommandContext
 * @brief Context for disconnect command
 */
typedef struct {
    bool terminate_debuggee;        /**< Whether to terminate the debuggee when disconnecting */
    bool suspend_debuggee;          /**< Whether to suspend the debuggee when disconnecting */
    bool restart;                   /**< Whether this disconnect is part of a restart sequence */
} DisconnectCommandContext;

/**
 * @struct DisassembleCommandContext
 * @brief Context for disassemble command
 */
typedef struct {
    const char* memory_reference;   /**< Memory reference to the function to disassemble (required) */
    uint64_t offset;                /**< Offset (in bytes) to add to the memory reference before disassembling (optional) */
    int instruction_offset;         /**< Offset (in instructions) to add to the memory reference before disassembling (optional) */
    int instruction_count;          /**< Number of instructions to disassemble (optional, defaults to 10) */
    bool resolve_symbols;           /**< Whether to return symbols with the disassembled instructions (optional, default: false) */
} DisassembleCommandContext;

/**
 * @struct ReadMemoryCommandContext
 * @brief Context for readMemory command
 */
typedef struct {
    const char* memory_reference;   /**< Memory reference (required) */
    uint64_t offset;                /**< Offset in bytes to add to the memory reference (optional) */
    size_t count;                   /**< Number of bytes to read (required) */
} ReadMemoryCommandContext;

/**
 * @struct WriteMemoryCommandContext
 * @brief Context for writeMemory command
 */
typedef struct {
    const char* memory_reference;   /**< Memory reference (required) */
    uint64_t offset;                /**< Offset in bytes to add to the memory reference (optional) */
    const char* data;               /**< Data to write in base64 encoding (required) */
    bool allow_partial;             /**< Whether to allow partial writes (optional) */
} WriteMemoryCommandContext;

/**
 * @struct ScopesCommandContext
 * @brief Context for scopes command
 */
typedef struct {
    int frame_id;                   /**< Stack frame ID for which to retrieve scopes (required) */
} ScopesCommandContext;

/**
 * @struct VariablesCommandContext
 * @brief Context for variables command
 */
typedef struct {
    int variables_reference;        /**< The variables reference to retrieve children for (required) */
    int filter;                     /**< Optional filter ("indexed" or "named") */
    int start;                      /**< Optional start index for paged requests */
    int count;                      /**< Optional number of variables to return */
    const char* format;             /**< Optional formatting hints */

     // Results
    DAPVariable *variable_array;       /**< Variables array to be filled by callback */
    int variable_count;             /**< Number of variables in the array */        
} VariablesCommandContext;

/**
 * @struct SetVariableCommandContext
 * @brief Context for setVariable command
 */
typedef struct {
    int variables_reference;        /**< The reference of the variable container (required) */
    const char* name;              /**< The name of the variable in the container (required) */
    const char* value;             /**< The value to set (required) */
    const char* format;            /**< Optional formatting hints */
} SetVariableCommandContext;

/**
 * @typedef DAPCommandCallback
 * @brief Function signature for command implementation callbacks
 * 
 * This is the interface between the DAP protocol handling and the actual debugger implementation.
 * The server calls these callbacks after parsing and validating the DAP protocol messages.
 * The debugger implementation (e.g. mock_server) provides these callbacks to implement the actual debugging functionality.
 * 
 * For initialize command:
 * - Called after protocol-level validation of initialize request
 * - Should set up debugger-specific capabilities and state
 * - Can access parsed client capabilities via server->client_capabilities
 * - Can modify server capabilities response via server->current_command context
 * 
 * @param server The DAP server instance containing command context and state
 * @return 0 on success, non-zero on failure
 */
typedef int (*DAPCommandCallback)(struct DAPServer *server);

/**
 * @struct DebuggerState
 * @brief Information about the current debugger state
 */
typedef struct {
    // Execution state information
    int program_counter;          /**< Current program counter value */
    int source_line;              /**< Current source line */
    int source_column;            /**< Current source column */
    bool has_stopped;             /**< Whether execution has stopped */
    char* stop_reason;            /**< Reason for stopping (if has_stopped is true) */    
    char* stop_description;       /**< Description for stopping (if has_stopped is true) */
    int current_thread_id;        /**< Current thread ID for execution control */

    // Program information
    const char* program_path;     /**< Current program file path */
    const char* source_path;      /**< Current source file path */
    const char* source_name;      /**< Current source file name */
    const char* map_path;         /**< Map file for debugging symbols */
    const char* working_directory;/**< Working directory for the debuggee */
    bool no_debug;                /**< Whether debugging is disabled */
    bool stop_at_entry;           /**< Whether to stop at the entry point */
    
    // Command line arguments
    char** args;                  /**< Command line arguments array */
    int args_count;               /**< Number of command line arguments */
    
    // User data
    void* user_data;              /**< User-defined data for the current state */
} DebuggerState;

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
    int sequence;            /**< Current sequence number */


    //int current_thread_id; /**< Current thread ID for execution control */
    //int current_line;      /**< Current source line */
    //int current_column;    /**< Current source column */
    //int current_pc;        /**< Current program counter */
    
    //char *program_path;

    // Debugging state information structure for storing callback results
    DebuggerState debugger_state;  /**< Current debugger state, updated by callbacks */

    int breakpoint_count;
    DAPBreakpoint *breakpoints;

    
    // Generic callback array for command implementations. MUST be set up the the DEBUGGER implementation.
    DAPCommandCallback command_callbacks[DAP_CMD_MAX]; /**< Callback functions for command implementation */
    
    // Keep existing command handlers for protocol parsing
    DAPCommandHandler command_handlers[DAP_CMD_MAX]; /**< Command handlers for protocol parsing */
    

    
    // Current command context - set before calling command_callbacks
    struct {
        DAPCommandType type;           /**< Current command type being processed */
        int request_seq;               /**< Request sequence number */
        
        // Command-specific data stored in a union to avoid using cJSON directly
        union {
            StepCommandContext step;                /**< Context for step commands */
            BreakpointCommandContext breakpoint;    /**< Context for breakpoint commands */
            ExceptionBreakpointCommandContext exception; /**< Context for exception breakpoints */
            LaunchCommandContext launch;            /**< Context for launch command */
            RestartCommandContext restart;          /**< Context for restart command */
            DisconnectCommandContext disconnect;    /**< Context for disconnect command */
            DisassembleCommandContext disassemble;  /**< Context for disassemble command */
            ReadMemoryCommandContext read_memory;   /**< Context for readMemory command */
            WriteMemoryCommandContext write_memory;  /**< Context for writeMemory command */
            ScopesCommandContext scopes;            /**< Context for scopes command */
            VariablesCommandContext variables;       /**< Context for variables command */
            SetVariableCommandContext set_variable; /**< Context for setVariable command */
            StackTraceCommandContext stack_trace;   /**< Context for stack trace command */
            // Add more command-specific contexts as needed
        } context;
    } current_command;

    // Client capabilities
    DAPClientCapabilities client_capabilities; /**< Capabilities reported by the client */
};

/**
 * @brief Output category enum for dap_server_send_output functions
 * 
 * The category determines how messages are styled and where they're displayed in the client.
 */
typedef enum {
    DAP_OUTPUT_CONSOLE,    // Normal debugger console output (default). Shows in Debug Console.
    DAP_OUTPUT_STDOUT,     // Standard output from the debuggee. Shows in Debug Console (often blue).
    DAP_OUTPUT_STDERR,     // Standard error from the debuggee. Shows in Debug Console (often red).
    DAP_OUTPUT_TELEMETRY,  // Telemetry data. Usually not displayed to users in Debug Console.
    DAP_OUTPUT_IMPORTANT,  // High-visibility output, often highlighted. Shows in Debug Console.
    DAP_OUTPUT_PROGRESS,   // Progress information (often with spinner/indicator). Shows in Debug UI.
    DAP_OUTPUT_LOG         // Log output from debugger itself. Shows in Debug Console (subdued).
} DAPOutputCategory;

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
int dap_server_send_response(DAPServer *server, DAPCommandType command, int sequence, int request_seq, bool success, cJSON *body);


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
 * @brief Send an output message to the debug console
 * 
 * Simplified version of dap_server_send_output_event that uses "console" as the category.
 * Useful for quick debug messages or informational output.
 * 
 * @param server Server instance
 * @param message The message to display in the debug console
 * @return 0 on success, non-zero on failure
 */
int dap_server_send_output(DAPServer *server, const char *message);

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
int dap_server_send_output_category(DAPServer *server, DAPOutputCategory category, const char *output);
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
                                bool is_local_process, const char *start_method);

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
int dap_server_send_thread_event(DAPServer *server, const char *reason, int thread_id);


/**
 * @brief Register a command implementation callback
 * @param server Server instance
 * @param command_id Command ID to register the callback for
 * @param callback The implementation callback function
 * @return 0 on success, non-zero on failure
 */
int dap_server_register_command_callback(DAPServer *server, DAPCommandType command_id, DAPCommandCallback callback);

/**
 * @brief Clean up resources used by the current command context
 * 
 * This function should be called after a command and its implementation have completed
 * to free any dynamically allocated memory in the command context.
 * 
 * @param server The DAP server instance
 */
void cleanup_command_context(DAPServer *server);

/**
 * @brief Send a welcome message when a client connects
 */

#endif // ND100X_DAP_SERVER_H