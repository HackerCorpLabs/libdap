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
    char* source_path;                  ///< Source file path
    char* source_name;                  ///< Source file name
    int line;                           ///< Line number in the source
    int column;                         ///< Column number in the source
    int end_line;                       ///< Optional end line number
    int end_column;                     ///< Optional end column number
    char* instruction_pointer_reference;  ///< Optional instruction pointer reference
    char* module_id;                     ///< Optional module ID
    DAPStackFramePresentationHint presentation_hint; ///< Optional presentation hint
    bool can_restart;                    ///< Whether the frame can be restarted
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
 * @brief Variable presentation hint kind
 */
typedef enum {
    DAP_VARIABLE_KIND_PROPERTY,      /**< Property */
    DAP_VARIABLE_KIND_METHOD,        /**< Method */
    DAP_VARIABLE_KIND_CLASS,         /**< Class */
    DAP_VARIABLE_KIND_DATA,          /**< Data */
    DAP_VARIABLE_KIND_EVENT,         /**< Event */
    DAP_VARIABLE_KIND_BASE_CLASS,    /**< Base class */
    DAP_VARIABLE_KIND_INNER_CLASS,   /**< Inner class */
    DAP_VARIABLE_KIND_INTERFACE,     /**< Interface */
    DAP_VARIABLE_KIND_MOST_DERIVED,  /**< Most derived class */
    DAP_VARIABLE_KIND_VIRTUAL,       /**< Virtual */
    DAP_VARIABLE_KIND_DATABREAKPOINT /**< Data breakpoint */
} DAPVariableKind;

/**
 * @brief Variable presentation attribute flags
 * 
 * These flags correspond to the attributes field in the VariablePresentationHint
 * object as defined in the Debug Adapter Protocol specification.
 */
typedef enum {
    DAP_VARIABLE_ATTR_NONE     = 0,         /**< No attributes */
    DAP_VARIABLE_ATTR_STATIC   = (1 << 0),  /**< Variable is static */
    DAP_VARIABLE_ATTR_CONSTANT = (1 << 1),  /**< Variable is a constant */
    DAP_VARIABLE_ATTR_READONLY = (1 << 2),  /**< Variable is read-only */
    DAP_VARIABLE_ATTR_RAWSTRING = (1 << 3), /**< String should not be escaped/processed */
    DAP_VARIABLE_ATTR_HASOBJECTID = (1 << 4), /**< Has an associated objectId (inspector/REPL) */
    DAP_VARIABLE_ATTR_CANHAVEOBJECTID = (1 << 5), /**< Might have an objectId */
    DAP_VARIABLE_ATTR_HASSIDEEFFECTS = (1 << 6), /**< Evaluating causes side effects */
    DAP_VARIABLE_ATTR_HASDATABREAKPOINT = (1 << 7), /**< Value is eligible for data breakpoint */
    DAP_VARIABLE_ATTR_HASCHILDREN = (1 << 8) /**< Variable has children */
} DAPVariableAttributes;

/**
 * @brief Variable presentation visibility
 */
typedef enum {
    DAP_VARIABLE_VISIBILITY_PUBLIC,     /**< Public visibility */
    DAP_VARIABLE_VISIBILITY_PRIVATE,    /**< Private visibility */
    DAP_VARIABLE_VISIBILITY_PROTECTED,  /**< Protected visibility */
    DAP_VARIABLE_VISIBILITY_INTERNAL,   /**< Internal visibility */
    DAP_VARIABLE_VISIBILITY_FINAL       /**< Final visibility */
} DAPVariableVisibility;

/**
 * @brief Variable presentation hint structure (replacing the enum)
 */
typedef struct {
    DAPVariableKind kind;                /**< Kind of variable */
    DAPVariableAttributes attributes;    /**< Attribute flags */
    DAPVariableVisibility visibility;    /**< Visibility type */
    bool has_kind;                       /**< Whether kind is set */
    bool has_visibility;                 /**< Whether visibility is set */
} DAPVariablePresentationHint;

/**
 * @brief Variable structure representing a variable or register
 * 
 * This structure is used to represent a variable or register as per DAP specification
 */
typedef struct DAPVariable {
    char* name;                      /**< Variable name (required) */
    char* value;                     /**< Variable value as string (required) */
    char* type;                      /**< Type name (optional) */
    int variables_reference;         /**< Reference ID for querying children (0 = no children) */
    int named_variables;             /**< Number of named child variables */
    int indexed_variables;           /**< Number of indexed child variables */
    char* evaluate_name;             /**< Expression that evaluates to this variable (optional) */
    DAPVariablePresentationHint presentation_hint; /**< UI hints (kind, attributes, visibility) */
    char* memory_reference;          /**< Memory address as string if variable represents memory (optional) */
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
    char* source_path;                  ///< Source file path
    char* source_name;                  ///< Source file name
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
    char* source_path;                  ///< Source file path
    char* source_name;                  ///< Source file name
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