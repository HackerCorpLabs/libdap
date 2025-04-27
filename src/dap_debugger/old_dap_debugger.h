/*
 * dap_debugger.h
 * Header file for Debug Adapter Protocol client
 */

/**
 * @file dap_debugger.h
 * @brief Client implementation for the Debug Adapter Protocol
 */

#ifndef DAP_CLIENT_H
#define DAP_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <cjson/cJSON.h>
#include "dap_protocol.h"
#include "dap_message.h"
#include "machine_dbg.h"
#include "dap_types.h"

/**
 * @brief Memory Ownership Rules
 * 
 * The following rules apply to memory management in this API:
 * 
 * 1. Client Structure:
 *    - Created with dap_debugger_create() (caller owns)
 *    - Freed with dap_debugger_free() (transfers ownership)
 *    - Must be freed even if initialization fails
 * 
 * 2. Request Arguments:
 *    - Created by caller using cJSON functions
 *    - Ownership remains with caller
 *    - Must be freed by caller after use
 * 
 * 3. Response Bodies:
 *    - Allocated by functions that take char** response_body
 *    - Ownership transferred to caller
 *    - Must be freed by caller using free()
 * 
 * 4. Result Structures:
 *    - Created by caller
 *    - Ownership remains with caller
 *    - Must be freed by caller
 *    - May contain allocated members that need freeing
 * 
 * 5. Arrays and Lists:
 *    - Created by functions that take pointer to array/length
 *    - Ownership transferred to caller
 *    - Must be freed by caller
 *    - May contain allocated members that need freeing
 * 
 * Example usage:
 * @code
 * // Creating and using a client
 * DAPClient* client = dap_debugger_create("localhost", 1234);
 * if (!client) {
 *     // Handle error
 * }
 * 
 * // Making a request
 * cJSON* args = cJSON_CreateObject();
 * cJSON_AddStringToObject(args, "key", "value");
 * 
 * char* response = NULL;
 * if (dap_debugger_send_request(client, "command", args, &response) == 0) {
 *     // Use response
 *     free(response);
 * }
 * 
 * cJSON_Delete(args);
 * dap_debugger_free(client);
 * @endcode
 */

/**
 * @brief Maximum size of a DAP message in bytes
 */
#define DAP_MAX_MESSAGE_SIZE 65536

/**
 * @brief Client structure for DAP communication
 * 
 * @note The structure owns all its members and will free them when dap_debugger_free() is called.
 */
typedef struct {
    int fd;                 ///< Socket file descriptor
    bool connected;         ///< Connection status
    char* host;            ///< Server hostname (owned by the structure)
    int port;              ///< Server port
    int seq;               ///< Sequence counter
    int timeout_ms;        ///< Request timeout in milliseconds
    void* debugger;        ///< Debugger-specific data
    int thread_id;         ///< Current thread ID
} DAPClient;

/**
 * @brief Create a new DAP client
 * 
 * @param host Server hostname (will be copied)
 * @param port Server port number
 * @return DAPClient* New client object (caller must free with dap_debugger_free())
 */
DAPClient* dap_debugger_create(const char* host, int port);

/**
 * @brief Free a DAP client
 * 
 * @param client Client to free (ownership transferred to this function)
 * 
 * @note This function will:
 *       - Disconnect if connected
 *       - Free the host string
 *       - Free the client structure
 */
void dap_debugger_free(DAPClient* client);

/**
 * @brief Connect to a DAP server
 * 
 * @param client Client to connect (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_connect(DAPClient* client);

/**
 * @brief Disconnect from a DAP server
 * 
 * @param client Client to disconnect (ownership remains with caller)
 * @param restart Whether to restart the debuggee
 * @param terminate_debuggee Whether to terminate the debuggee
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_disconnect(DAPClient* client, bool restart, bool terminate_debuggee, DAPDisconnectResult* result);

/**
 * @brief Send a request to the DAP server
 * 
 * @param client Client to use (ownership remains with caller)
 * @param command Command to send (ownership remains with caller)
 * @param arguments Request arguments (ownership remains with caller)
 * @param response_body Output parameter for response (ownership transferred to caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_send_request(DAPClient* client, DAPCommandType command, cJSON* arguments, char** response_body);

/**
 * @brief Initialize the debug session
 * 
 * @param client Client to initialize (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_initialize(DAPClient* client);

/**
 * @brief Launch a program
 * 
 * @param client Client to use (ownership remains with caller)
 * @param program_path Path to program (ownership remains with caller)
 * @param stop_at_entry Whether to stop at entry point
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_launch(DAPClient* client, const char* program_path, bool stop_at_entry);

/**
 * @brief Set breakpoints in a source file
 * 
 * @param client Client to use (ownership remains with caller)
 * @param source_path Source file path (ownership remains with caller)
 * @param breakpoints Array of breakpoints (ownership remains with caller)
 * @param num_breakpoints Number of breakpoints
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_set_breakpoints(DAPClient* client, const char* source_path, const DAPSourceBreakpoint* breakpoints, size_t num_breakpoints, DAPSetBreakpointsResult* result);

/**
 * @brief Signal the end of configuration
 * 
 * @param client Client to use (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_configuration_done(DAPClient* client);

/**
 * @brief Get thread information
 * 
 * @param client Client to use (ownership remains with caller)
 * @param threads Output array of threads (ownership transferred to caller)
 * @param thread_count Output number of threads
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_get_threads(DAPClient* client, DAPThread** threads, int* thread_count);

/**
 * @brief Get stack trace for a thread
 * 
 * @param client Client to use (ownership remains with caller)
 * @param thread_id Thread ID
 * @param frames Output array of frames (ownership transferred to caller)
 * @param frame_count Output number of frames
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_get_stack_trace(DAPClient* client, int thread_id, DAPStackFrame** frames, int* frame_count);

/**
 * @brief Continue execution
 * 
 * @param client Pointer to the client
 * @param thread_id Thread ID (must be 1 for single thread)
 * @param single_thread Whether to continue only the specified thread
 * @param result Output result structure
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_continue(DAPClient* client, int thread_id, bool single_thread, DAPContinueResult* result);

/**
 * @brief Step into the next statement
 * @param client The DAP client instance
 * @param thread_id The ID of the thread to step
 * @param target_id Optional target ID for stepping into a specific function
 * @param granularity Optional granularity level for stepping (e.g. "statement", "line", "instruction")
 * @param result Pointer to store the step-in result
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_step_in(DAPClient* client, int thread_id, const char* target_id, const char* granularity, DAPStepInResult* result);

/**
 * @brief Step out
 * 
 * @param client Client to use (ownership remains with caller)
 * @param thread_id Thread ID
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_step_out(DAPClient* client, int thread_id, DAPStepOutResult* result);

/**
 * @brief Pause execution
 * 
 * @param client Client to use (ownership remains with caller)
 * @param thread_id Thread ID (0 for all threads)
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_pause(DAPClient* client, int thread_id, DAPPauseResult* result);

/**
 * @brief Set the request timeout
 * 
 * @param client Client to use (ownership remains with caller)
 * @param timeout_ms Timeout in milliseconds
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_set_timeout(DAPClient* client, int timeout_ms);

/**
 * @brief Temporarily increase the timeout for a specific operation
 * 
 * @param client Client to use (ownership remains with caller)
 * @param new_timeout_ms New timeout in milliseconds
 * @param old_timeout_ms Pointer to store the old timeout (optional)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_increase_timeout(DAPClient* client, int new_timeout_ms, int* old_timeout_ms);

/**
 * @brief Get variables in a scope
 * 
 * @param client Client to use (ownership remains with caller)
 * @param variables_reference Variables reference
 * @param start Start index
 * @param count Number of variables
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_get_variables(DAPClient* client, int variables_reference, int start, int count, DAPGetVariablesResult* result);

/**
 * @brief Evaluate an expression
 * 
 * @param client Client to use (ownership remains with caller)
 * @param expression Expression to evaluate (ownership remains with caller)
 * @param frame_id Frame ID
 * @param context Evaluation context (ownership remains with caller)
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_evaluate(DAPClient* client, const char* expression, int frame_id, const char* context, DAPEvaluateResult* result);

/**
 * @brief Get scopes for a stack frame
 * 
 * @param client Client to use (ownership remains with caller)
 * @param frame_id Frame ID
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_get_scopes(DAPClient* client, int frame_id, DAPGetScopesResult* result);

/**
 * @brief Set a variable value
 * 
 * @param client Client to use (ownership remains with caller)
 * @param variables_reference Variables reference
 * @param name Variable name (ownership remains with caller)
 * @param value New value (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_set_variable(DAPClient* client, int variables_reference, const char* name, const char* value);

/**
 * @brief Set an expression value
 * 
 * @param client Client to use (ownership remains with caller)
 * @param expression Expression to set (ownership remains with caller)
 * @param value New value (ownership remains with caller)
 * @param frame_id Frame ID
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_set_expression(DAPClient* client, const char* expression, const char* value, int frame_id);

/**
 * @brief Write register values
 * 
 * @param client Client to use (ownership remains with caller)
 * @param registers Array of register values (ownership remains with caller)
 * @param register_count Number of registers
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_write_registers(DAPClient* client, const uint32_t* registers, size_t register_count);

/**
 * @brief Get loaded sources
 * 
 * @param client Client to use (ownership remains with caller)
 * @param sources Output array of sources (ownership transferred to caller)
 * @param source_count Output number of sources
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_get_loaded_sources(DAPClient* client, DAPSource** sources, size_t* source_count);

/**
 * @brief Step back
 * 
 * @param client Client to use (ownership remains with caller)
 * @param thread_id Thread ID
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_step_back(DAPClient* client, int thread_id, DAPStepBackResult* result);

/**
 * @brief Set instruction breakpoints
 * 
 * @param client Client to use (ownership remains with caller)
 * @param breakpoints Array of breakpoints (ownership remains with caller)
 * @param num_breakpoints Number of breakpoints
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_set_instruction_breakpoints(DAPClient* client, const DAPInstructionBreakpoint* breakpoints, size_t num_breakpoints, DAPSetInstructionBreakpointsResult* result);

/**
 * @brief Get source content
 * 
 * @param client Client to use (ownership remains with caller)
 * @param source_path Source path (ownership remains with caller)
 * @param source_reference Source reference
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_source(DAPClient* client, const char* source_path, int source_reference, DAPSourceResult* result);

/**
 * @brief Get module information
 * 
 * @param client Client to use (ownership remains with caller)
 * @param start_module Start module index
 * @param module_count Number of modules
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_modules(DAPClient* client, int start_module, int module_count, DAPModulesResult* result);

/**
 * @brief Load source information
 * 
 * @param client Client to use (ownership remains with caller)
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_load_sources(DAPClient* client, DAPLoadSourcesResult* result);

/**
 * @brief Read memory
 * 
 * @param client Client to use (ownership remains with caller)
 * @param memory_reference Memory reference (ownership remains with caller)
 * @param offset Memory offset
 * @param count Number of bytes to read
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_read_memory(DAPClient* client, const char* memory_reference, uint64_t offset, size_t count, DAPReadMemoryResult* result);

/**
 * @brief Write memory
 * 
 * @param client Client to use (ownership remains with caller)
 * @param memory_reference Memory reference (ownership remains with caller)
 * @param offset Memory offset
 * @param data Data to write (ownership remains with caller)
 * @param allow_partial Whether to allow partial writes
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_write_memory(DAPClient* client, const char* memory_reference, uint64_t offset, const char* data, bool allow_partial, DAPWriteMemoryResult* result);

/**
 * @brief Disassemble memory
 * 
 * @param client Client to use (ownership remains with caller)
 * @param memory_reference Memory reference (ownership remains with caller)
 * @param offset Memory offset
 * @param instruction_offset Instruction offset
 * @param instruction_count Number of instructions
 * @param resolve_symbols Whether to resolve symbols
 * @param result Output result structure (ownership remains with caller)
 * @return int 0 on success, -1 on failure
 */
int dap_debugger_disassemble(DAPClient* client, const char* memory_reference, uint64_t offset, size_t instruction_offset, size_t instruction_count, bool resolve_symbols, DAPDisassembleResult* result);

#endif /* DAP_CLIENT_H */ 