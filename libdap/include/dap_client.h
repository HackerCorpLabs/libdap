/**
 * @file dap_client.h
 * @brief DAP client interface
 */

#ifndef DAP_CLIENT_H
#define DAP_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <cjson/cJSON.h>
#include "dap_types.h"
#include "dap_protocol.h"
#include "dap_error.h"
#include "dap_transport.h"

/**
 * @brief DAP client structure
 */
typedef struct {
    char* host;              ///< Server hostname
    int port;                ///< Server port number
    int fd;                  ///< Socket file descriptor (deprecated, kept for compatibility)
    bool connected;          ///< Connection state
    uint32_t seq;            ///< Request sequence number
    int timeout_ms;          ///< Timeout for requests in milliseconds
    bool debug_mode;         ///< Debug mode flag
    char* program_path;      ///< Currently loaded program path
    int thread_id;           ///< Current thread ID
    DAPBreakpoint* breakpoints; ///< Array of breakpoints
    int num_breakpoints;     ///< Number of breakpoints
    DAPTransport* transport; ///< Transport layer for communications
    
} DAPClient;
/**
 * @brief Initialize the client structure
 * 
 * @param client Pointer to the client structure
 * @param host Server hostname
 * @param port Server port number
 * @param timeout_ms Timeout in milliseconds
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_init(DAPClient* client, const char* host, int port, int timeout_ms);

/**
 * @brief Create a new DAP client
 * 
 * @param host Server hostname
 * @param port Server port number
 * @return DAPClient* Pointer to the created client, NULL on failure
 */
DAPClient* dap_client_create(const char* host, int port);

/**
 * @brief Connect to a DAP server
 * 
 * @param client Pointer to the client
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_connect(DAPClient* client);

/**
 * @brief Disconnect from a DAP server
 * 
 * @param client Pointer to the client
 * @param restart Whether to restart the debuggee
 * @param terminate_debuggee Whether to terminate the debuggee
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_disconnect(DAPClient* client, bool restart, bool terminate_debuggee, DAPDisconnectResult* result);

/**
 * @brief Free a DAP client
 * 
 * @param client Pointer to the client
 */
void dap_client_free(DAPClient* client);

/**
 * @brief Send a DAP request and wait for response
 * 
 * @param client Pointer to the client
 * @param command Command type
 * @param arguments Request arguments (cJSON object, may be NULL)
 * @param response_body Output parameter for response body (caller must free)
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_send_request(DAPClient* client, DAPCommandType command, cJSON* arguments, char** response_body);

/**
 * @brief Initialize the debug session
 * 
 * @param client Pointer to the client
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_initialize(DAPClient* client);

/**
 * @brief Launch a program
 * 
 * @param client Pointer to the client
 * @param program_path Path to the program to launch
 * @param stop_at_entry Whether to stop at program entry point
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_launch(DAPClient* client, const char* program_path, bool stop_at_entry);



/**
 * @brief Signal the end of configuration
 * 
 * @param client Pointer to the client
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_configuration_done(DAPClient* client);

/**
 * @brief Get thread information
 * 
 * @param client Pointer to the client
 * @param threads Output array of threads (caller must free)
 * @param count Output number of threads
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_get_threads(DAPClient* client, DAPThread** threads, int* count);

/**
 * @brief Get stack trace for a thread
 * 
 * @param client Pointer to the client
 * @param thread_id Thread ID
 * @param frames Output array of frames (caller must free)
 * @param frame_count Output number of frames
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_get_stack_trace(DAPClient* client, int thread_id, 
                              DAPStackFrame** frames, int* frame_count);

/**
 * @brief Continue execution
 * 
 * @param client Pointer to the client
 * @param thread_id Thread ID
 * @param single_thread Whether to continue only the specified thread
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_continue(DAPClient* client, int thread_id, bool single_thread,
                       DAPContinueResult* result);

/**
 * @brief Step into
 * 
 * @param client Pointer to the client
 * @param thread_id Thread ID
 * @param target_id Target ID (optional)
 * @param granularity Step granularity (optional)
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_step_in(DAPClient* client, int thread_id, const char* target_id,
                      const char* granularity, DAPStepInResult* result);

/**
 * @brief Step over (next)
 * 
 * Executes one step (of the specified granularity) in the current thread, stepping over
 * function calls rather than stepping into them. The debug adapter will automatically
 * continue until the next line of code is reached. This is commonly known as the
 * "next" command in many debuggers.
 *
 * @param client Pointer to the client
 * @param thread_id Thread ID to step
 * @param granularity Step granularity (optional, one of "statement", "line", "instruction")
 * @param single_thread Whether to continue only the specified thread
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_next(DAPClient* client, int thread_id, const char* granularity, 
                   bool single_thread, DAPStepResult* result);

/**
 * @brief Step out of the current function
 * 
 * Resumes execution until the current function returns. The debugger will stop
 * at the return address of the current function. This is useful for quickly
 * exiting a function when you're not interested in its remaining execution.
 * 
 * @param client Pointer to the client
 * @param thread_id Thread ID to step out from
 * @param result Output result structure containing success status and whether
 *               all threads were stopped
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_step_out(DAPClient* client, int thread_id, DAPStepOutResult* result);

/**
 * @brief Step back to the previous execution point
 * 
 * Moves execution backwards to the previous execution point. This is only
 * supported if the debugger has reverse execution capabilities. The debugger
 * will stop at the previous execution point, allowing inspection of the
 * program state before the current point.
 * 
 * @param client Pointer to the client
 * @param thread_id Thread ID to step back from
 * @param result Output result structure containing success status and whether
 *               all threads were stopped
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_step_back(DAPClient* client, int thread_id, DAPStepBackResult* result);

/**
 * @brief Pause execution
 * 
 * @param client Pointer to the client
 * @param thread_id Thread ID
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_pause(DAPClient* client, int thread_id, DAPPauseResult* result);

/**
 * @brief Get scopes for a stack frame
 * 
 * @param client Pointer to the client
 * @param frame_id Frame ID
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_get_scopes(DAPClient* client, int frame_id, DAPGetScopesResult* result);

/**
 * @brief Get variables for a variables reference
 * 
 * @param client Pointer to the client
 * @param variables_reference Variables reference ID
 * @param start Start index for paging
 * @param count Number of variables to retrieve
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_get_variables(DAPClient* client, int variables_reference, int start, int count, DAPGetVariablesResult* result);

/**
 * @brief Free a variables result structure
 * 
 * @param result Result structure to free
 */
void dap_get_variables_result_free(DAPGetVariablesResult* result);

/**
 * @brief Set variable value
 * 
 * @param client Pointer to the client
 * @param variables_reference Variables reference
 * @param name Variable name
 * @param value New value
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_set_variable(DAPClient* client, int variables_reference,
                           const char* name, const char* value);

/**
 * @brief Set expression value
 * 
 * @param client Pointer to the client
 * @param expression Expression to evaluate
 * @param value New value
 * @param frame_id Frame ID
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_set_expression(DAPClient* client, const char* expression,
                            const char* value, int frame_id);


/**
 * @brief Step back
 * 
 * @param client Pointer to the client
 * @param thread_id Thread ID
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_step_back(DAPClient* client, int thread_id, DAPStepBackResult* result);

/**
 * @brief Set instruction breakpoints
 * 
 * @param client Pointer to the client
 * @param breakpoints Array of breakpoints
 * @param num_breakpoints Number of breakpoints
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_set_instruction_breakpoints(DAPClient* client,
                                         const DAPInstructionBreakpoint* breakpoints,
                                         size_t num_breakpoints,
                                         DAPSetInstructionBreakpointsResult* result);



/**
 * @brief Get loaded modules
 * 
 * @param client Pointer to the client
 * @param start_module Starting module index
 * @param module_count Number of modules to get
 * @param result Output result structure
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_modules(DAPClient* client, int start_module, int module_count, DAPModulesResult* result);

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
int dap_client_read_memory(DAPClient* client, const char* memory_reference, uint64_t offset, size_t count, DAPReadMemoryResult* result);

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
int dap_client_write_memory(DAPClient* client, const char* memory_reference, uint64_t offset, const char* data, bool allow_partial, DAPWriteMemoryResult* result);

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
int dap_client_disassemble(DAPClient* client, const char* memory_reference, uint64_t offset, size_t instruction_offset, size_t instruction_count, bool resolve_symbols, DAPDisassembleResult* result);

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
int dap_client_evaluate(DAPClient* client, const char* expression, int frame_id, const char* context, DAPEvaluateResult* result);

/**
 * @brief Clean up an evaluate result structure
 * 
 * @param result Pointer to the result structure to clean up
 */
void dap_evaluate_result_free(DAPEvaluateResult* result);

/**
 * @brief Temporarily increase the timeout for a specific operation
 * 
 * @param client Pointer to the client
 * @param new_timeout_ms New timeout in milliseconds
 * @param old_timeout_ms Pointer to store the old timeout (optional)
 * @return int DAP_ERROR_NONE on success, error code on failure
 */
int dap_client_increase_timeout(DAPClient* client, int new_timeout_ms,
                              int* old_timeout_ms);



// Add these command types
#define DAP_CMD_STOPPED "stopped"
#define DAP_CMD_TERMINATED "terminated"
#define DAP_CMD_EXITED "exited"

// Add these function declarations
int dap_client_step(DAPClient* client, int thread_id, bool single_thread, DAPStepResult* result);
int dap_client_threads(DAPClient* client, DAPGetThreadsResult* result);
int dap_client_receive_message(DAPClient* client, cJSON** message);
int dap_client_stack_trace(DAPClient* client, int thread_id, DAPStackFrame** frames, size_t* frame_count);

/**
 * @brief Process a received DAP event
 * 
 * @param client Pointer to the client
 * @param event_json JSON object containing the event data
 * @return int 0 on success, -1 on failure
 */
int dap_client_handle_event(DAPClient* client, cJSON* event_json);

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
                                       DAPSetExceptionBreakpointsResult* result);

#endif /* DAP_CLIENT_H */ 