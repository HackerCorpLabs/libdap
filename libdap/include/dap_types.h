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
 * @file dap_types.h
 * @brief Type definitions for the DAP library
 */

#ifndef DAP_TYPES_H
#define DAP_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include "dap_protocol.h"

/**
 * @brief Naming Convention
 * 
 * This library uses snake_case for all identifiers (variables, functions, structure members, etc.).
 * This includes:
 * - Structure member names (e.g., variables_reference, source_reference)
 * - Function names (e.g., dap_client_send_request)
 * - Variable names (e.g., num_breakpoints)
 * - Enum values (e.g., DAP_SOURCE_PRESENTATION_NORMAL)
 * 
 * This convention is consistently applied throughout the codebase to maintain
 * readability and consistency.
 */

// NOTE: This implementation only supports a single thread and stack frame
// Multi-threading and multiple stack frames are not supported

// Thread state enumeration - only RUNNING is used in single-thread mode
typedef enum {
    DAP_THREAD_STATE_RUNNING,    // Thread is running
    DAP_THREAD_STATE_STOPPED,    // Thread is stopped (e.g. at breakpoint)
    DAP_THREAD_STATE_TERMINATED  // Thread has terminated
} DAPThreadState;

/**
 * @brief Presentation hint for source files
 */
typedef enum {
    DAP_SOURCE_PRESENTATION_NORMAL,
    DAP_SOURCE_PRESENTATION_EMPHASIZE,
    DAP_SOURCE_PRESENTATION_DEEMPHASIZE
} DAPSourcePresentationHint;

/**
 * @brief Origin of the source
 */
typedef enum {
    DAP_SOURCE_ORIGIN_GENERATED,
    DAP_SOURCE_ORIGIN_DEPLOYED,
    DAP_SOURCE_ORIGIN_UNKNOWN
} DAPSourceOrigin;

/**
 * @brief Source checksum algorithm
 */
typedef enum {
    DAP_CHECKSUM_MD5,
    DAP_CHECKSUM_SHA1,
    DAP_CHECKSUM_SHA256
} DAPChecksumAlgorithm;

/**
 * @brief Source checksum structure
 */
typedef struct {
    DAPChecksumAlgorithm algorithm;
    char* checksum;
} DAPChecksum;

/**
 * @brief Source structure representing a source file
 */
typedef struct DAPSource {
    char* name;                ///< Name of the source file
    char* path;                ///< Full path to the source file
    int source_reference;      ///< Optional source reference number
    DAPSourcePresentationHint presentation_hint; ///< Presentation hint
    DAPSourceOrigin origin;    ///< Origin of the source
    struct DAPSource* sources; ///< Optional array of sub-sources
    size_t num_sources;        ///< Number of sub-sources
    char* adapter_data;        ///< Optional adapter-specific data
    bool is_optimized;         ///< Whether the source is optimized
    bool is_user_code;         ///< Whether the source is user code
    char* version;             ///< Optional version string
    char* symbol_status;       ///< Optional symbol status
    char* symbol_file_path;    ///< Optional path to symbol file
    char* date_time_stamp;     ///< Optional timestamp
    char* address_range;       ///< Optional address range
    DAPChecksum* checksums;    ///< Optional array of checksums
    size_t num_checksums;      ///< Number of checksums
} DAPSource;

/**
 * @brief Stack frame presentation hint
 */
typedef enum {
    DAP_FRAME_PRESENTATION_NORMAL,
    DAP_FRAME_PRESENTATION_LABEL,
    DAP_FRAME_PRESENTATION_SUBTLE
} DAPStackFramePresentationHint;

/**
 * @brief Stack frame structure representing a frame in the call stack
 */
typedef struct DAPStackFrame {
    int id;                             ///< Unique identifier for the frame
    char* name;                         ///< Name of the frame (function name)
    DAPSource* source;                  ///< Optional source of the frame
    int line;                           ///< Line number in the source
    int column;                         ///< Column number in the source
    int endLine;                        ///< Optional end line number
    int endColumn;                      ///< Optional end column number
    char* instructionPointerReference;  ///< Optional instruction pointer reference
    char* moduleId;                     ///< Optional module ID
    DAPStackFramePresentationHint presentationHint; ///< Optional presentation hint
    bool canRestart;                    ///< Whether the frame can be restarted
} DAPStackFrame;

/**
 * @brief Scope structure representing a variable scope
 */
typedef struct DAPScope {
    char* name;                ///< Name of the scope
    int variables_reference;   ///< Reference ID for variables in this scope
    int named_variables;       ///< Number of named child variables
    int indexed_variables;     ///< Number of indexed child variables
    bool expensive;            ///< Whether the scope is expensive to retrieve
    char* source_path;         ///< Source file path
    int line;                  ///< Line number
    int column;                ///< Column number
    int end_line;             ///< End line number
    int end_column;           ///< End column number
} DAPScope;

/**
 * @brief Variable presentation hint
 */
typedef enum {
    DAP_VARIABLE_PRESENTATION_NORMAL,
    DAP_VARIABLE_PRESENTATION_READONLY,
    DAP_VARIABLE_PRESENTATION_HIDDEN
} DAPVariablePresentationHint;

/**
 * @brief Variable structure representing a debug variable
 */
typedef struct DAPVariable {
    char* name;                         ///< Name of the variable
    char* value;                        ///< Value of the variable
    char* type;                         ///< Type of the variable
    int variables_reference;            ///< Optional reference to child variables
    int named_variables;                ///< Number of named child variables
    int indexed_variables;              ///< Number of indexed child variables
    char* memory_reference;             ///< Optional memory reference
    bool evaluatable;                   ///< Whether the variable can be evaluated
    char* evaluate_name;                ///< Optional expression to evaluate
    DAPVariablePresentationHint presentation_hint; ///< Optional presentation hint
    int value_location_reference;       ///< Optional reference to the variable's location
} DAPVariable;

/**
 * @brief Thread structure representing a debug thread
 */
typedef struct DAPThread {
    int id;           // Always 1 for single thread
    char* name;       // Thread name (always "main")
    DAPThreadState state;  // Always RUNNING in single-thread mode
} DAPThread;

/**
 * @brief Breakpoint structure representing a breakpoint
 */
typedef struct DAPBreakpoint {
    int id;                             ///< Unique identifier for the breakpoint
    bool verified;                      ///< Whether the breakpoint is verified
    char* message;                      ///< Optional message about the breakpoint
    DAPSource* source;                  ///< Source of the breakpoint
    int line;                           ///< Line number in the source
    int column;                         ///< Optional column number in the source
    int end_line;                       ///< Optional end line number
    int end_column;                     ///< Optional end column number
    char* instruction_reference;        ///< Optional instruction reference
    int offset;                         ///< Optional offset from instruction reference
    char* condition;                    ///< Optional condition expression
    char* hit_condition;                ///< Optional hit condition expression
    char* log_message;                  ///< Optional log message
} DAPBreakpoint;

/**
 * @brief Module structure representing a loaded module
 */
typedef struct {
    char* id;                ///< Unique identifier for the module
    char* name;              ///< A name of the module
    char* path;              ///< Path to the module
    bool is_optimized;       ///< True if the module is optimized
    bool is_user_code;       ///< True if the module is considered 'user code'
    char* version;           ///< Version of the module
    char* symbol_status;     ///< Status of the symbols
    char* symbol_file_path;  ///< Path to the symbol file
    char* date_time_stamp;   ///< Timestamp of the module
    char* address_range;     ///< Address range covered by this module
} DAPModule;

/**
 * @brief Disassembled instruction structure
 */
struct DAPDisassembledInstruction {
    char* address;                      ///< The address of the instruction
    char* instruction_bytes;            ///< Raw bytes representing the instruction
    char* instruction;                  ///< Text representing the instruction
    char* symbol;                       ///< Name of the symbol
    DAPSource* location;                ///< Source location
    int line;                           ///< Line number
    int column;                         ///< Column number
    int end_line;                       ///< End line number
    int end_column;                     ///< End column number
};

// Forward declarations
typedef struct DAPDisassembledInstruction DAPDisassembledInstruction;

// Result types for various DAP responses
typedef struct {
    bool success;
    char* message;
} DAPResult;

typedef struct {
    DAPResult base;
    bool supports_configuration_done;
    bool supports_terminate_request;
    bool supports_restart_request;
    bool supports_set_variable;
    bool supports_set_expression;
    bool supports_read_memory;
    bool supports_write_memory;
    bool supports_disassemble;
    bool supports_instruction_breakpoints;
    bool supports_stepping_granularity;
    bool supports_terminate_threads;
    bool supports_exception_filters;
} DAPInitializeResult;

typedef struct {
    DAPResult base;
    bool all_threads_continued;
} DAPContinueResult;

typedef struct {
    DAPResult base;
    bool all_threads_stopped;
} DAPStepResult;

typedef struct {
    DAPResult base;
    int thread_id;              ///< ID of the thread that was paused
    const char* reason;         ///< Reason for the pause
    bool all_threads_stopped;   ///< Whether all threads were stopped
} DAPPauseResult;

typedef struct {
    DAPResult base;
    DAPBreakpoint* breakpoints;
    size_t num_breakpoints;
} DAPSetBreakpointsResult;

typedef struct {
    DAPResult base;
    DAPBreakpoint* breakpoints;
    size_t num_breakpoints;
} DAPSetFunctionBreakpointsResult;

typedef struct {
    DAPResult base;
    DAPBreakpoint* breakpoints;
    size_t num_breakpoints;
} DAPSetExceptionBreakpointsResult;

typedef struct {
    DAPResult base;
    DAPBreakpoint* breakpoints;
    size_t num_breakpoints;
} DAPSetInstructionBreakpointsResult;

typedef struct {
    DAPResult base;
    DAPStackFrame* frames;
    size_t num_frames;
} DAPStackTraceResult;

typedef struct {
    DAPResult base;
    DAPScope* scopes;
    size_t num_scopes;
} DAPGetScopesResult;

typedef struct {
    DAPResult base;
    DAPVariable* variables;
    size_t num_variables;
} DAPGetVariablesResult;

typedef struct {
    DAPResult base;
    char* result;
    char* type;
    int variables_reference;
} DAPEvaluateResult;

typedef struct {
    DAPResult base;
    DAPThread* threads;
    size_t num_threads;
} DAPGetThreadsResult;

typedef struct {
    DAPResult base;
    DAPSource* sources;
    size_t num_sources;
} DAPLoadSourcesResult;

typedef struct {
    DAPResult base;
    char* content;
    char* mime_type;
} DAPSourceResult;

typedef struct {
    DAPResult base;
    DAPModule* modules;
    size_t num_modules;
} DAPModulesResult;

typedef struct {
    DAPResult base;
    char* address;
    size_t unreadable_bytes;
    char* data;
} DAPReadMemoryResult;

typedef struct {
    DAPResult base;
    size_t bytes_written;
    uint64_t offset;
} DAPWriteMemoryResult;

typedef struct {
    DAPResult base;
    DAPDisassembledInstruction* instructions;
    size_t num_instructions;
} DAPDisassembleResult;

// Step result types
typedef struct {
    DAPResult base;
    bool all_threads_stopped;
} DAPStepInResult;

typedef struct {
    DAPResult base;
    bool all_threads_stopped;
} DAPStepOutResult;

typedef struct {
    DAPResult base;
    bool all_threads_stopped;
} DAPStepBackResult;

// Disconnect result
typedef struct {
    DAPResult base;            ///< Base result structure
    bool restart;              ///< Whether to restart the debuggee
    bool terminate_debuggee;   ///< Whether to terminate the debuggee
} DAPDisconnectResult;

// Source breakpoint structure
typedef struct {
    int line;                ///< Line number
    int column;              ///< Column number
    char* condition;         ///< Condition expression
    char* hit_condition;     ///< Hit condition expression
    char* log_message;       ///< Log message
} DAPSourceBreakpoint;

// Instruction breakpoint structure
typedef struct {
    char* instruction_reference; ///< Instruction reference
    int offset;                ///< Offset from instruction reference
    char* condition;           ///< Condition expression
    char* hit_condition;       ///< Hit condition expression
} DAPInstructionBreakpoint;

/**
 * @brief Free memory allocated for a scopes result
 * 
 * @param result Result to free
 */
void dap_get_scopes_result_free(DAPGetScopesResult* result);

/**
 * @brief Free memory allocated for a disassemble result
 * 
 * @param result Result to free
 */
void dap_disassemble_result_free(DAPDisassembleResult* result);

#endif // DAP_TYPES_H 