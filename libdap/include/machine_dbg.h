/**
 * @file machine_dbg.h
 * @brief Machine debugger interface definitions
 */

#ifndef ND100X_MACHINE_DBG_H
#define ND100X_MACHINE_DBG_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Breakpoint structure
 */
typedef struct {
    uint16_t address;           /**< Breakpoint address */
    bool enabled;               /**< Whether breakpoint is enabled */
    char* condition;            /**< Optional condition expression */
    int hit_count;              /**< Number of times the breakpoint has been hit */
    int hit_condition;          /**< Number of hits required to trigger the breakpoint */
    char* log_message;          /**< Optional log message */
} MachineBreakpoint;

/**
 * @brief Stack frame structure
 */
typedef struct {
    int id;                     /**< Frame ID */
    char* name;                 /**< Frame name (function name) */
    uint16_t address;           /**< Frame instruction address */
    char* source_file;          /**< Source file path */
    int line;                   /**< Source line number */
    int column;                 /**< Source column number */
} MachineStackFrame;

/**
 * @brief Thread structure
 */
typedef struct {
    int id;                     /**< Thread ID */
    char* name;                 /**< Thread name */
    bool is_running;            /**< Whether thread is running */
} MachineThread;

/**
 * @brief Variable structure
 */
typedef struct {
    char* name;                 /**< Variable name */
    char* value;                /**< Variable value as string */
    char* type;                 /**< Variable type */
    bool has_children;          /**< Whether variable has children */
    int reference;              /**< Reference ID for variables with children */
} MachineVariable;

/**
 * @brief Machine debugger context
 */
typedef struct {
    bool is_initialized;        /**< Whether debugger is initialized */
    bool is_running;            /**< Whether target is running */
    bool is_attached;           /**< Whether debugger is attached to target */
    char* program_path;         /**< Path to program being debugged */
    int thread_count;           /**< Number of threads */
    MachineThread* threads;     /**< Array of threads */
    int breakpoint_count;       /**< Number of breakpoints */
    MachineBreakpoint* breakpoints; /**< Array of breakpoints */
    uint16_t pc;                /**< Program counter */
    uint16_t fp;                /**< Frame pointer */
    uint16_t sp;                /**< Stack pointer */
    void* machine_instance;     /**< Pointer to machine instance */
} MachineDebugger;

/**
 * @brief Initialize the machine debugger
 * 
 * @return MachineDebugger* Pointer to initialized debugger
 */
MachineDebugger* machine_dbg_init(void);

/**
 * @brief Free the machine debugger
 * 
 * @param dbg Pointer to debugger
 */
void machine_dbg_free(MachineDebugger* dbg);

/**
 * @brief Connect the debugger to a running machine instance
 * 
 * @param dbg Pointer to debugger
 * @param machine_instance Pointer to machine instance
 * @return int 0 on success, -1 on failure
 */
int machine_dbg_connect(MachineDebugger* dbg, void* machine_instance);

/**
 * @brief Launch a program in the debugger
 * 
 * @param dbg Pointer to debugger
 * @param program_path Path to program
 * @param stop_at_entry Whether to stop at program entry point
 * @return int 0 on success, -1 on failure
 */
int machine_dbg_launch(MachineDebugger* dbg, const char* program_path, bool stop_at_entry);

/**
 * @brief Set breakpoint at specified address
 * 
 * @param dbg Pointer to debugger
 * @param address Memory address for breakpoint
 * @param condition Optional breakpoint condition
 * @return int Breakpoint ID on success, -1 on failure
 */
int machine_dbg_set_breakpoint(MachineDebugger* dbg, uint16_t address, const char* condition);

/**
 * @brief Remove breakpoint
 * 
 * @param dbg Pointer to debugger
 * @param breakpoint_id Breakpoint ID
 * @return int 0 on success, -1 on failure
 */
int machine_dbg_remove_breakpoint(MachineDebugger* dbg, int breakpoint_id);

/**
 * @brief Continue execution
 * 
 * @param dbg Pointer to debugger
 * @param thread_id Thread ID or 0 for all threads
 * @return int 0 on success, -1 on failure
 */
int machine_dbg_continue(MachineDebugger* dbg, int thread_id);

/**
 * @brief Step to next source line
 * 
 * @param dbg Pointer to debugger
 * @param thread_id Thread ID
 * @return int 0 on success, -1 on failure
 */
int machine_dbg_step_over(MachineDebugger* dbg, int thread_id);

/**
 * @brief Step into function
 * 
 * @param dbg Pointer to debugger
 * @param thread_id Thread ID
 * @return int 0 on success, -1 on failure
 */
int machine_dbg_step_in(MachineDebugger* dbg, int thread_id);

/**
 * @brief Step out of current function
 * 
 * @param dbg Pointer to debugger
 * @param thread_id Thread ID
 * @return int 0 on success, -1 on failure
 */
int machine_dbg_step_out(MachineDebugger* dbg, int thread_id);

/**
 * @brief Pause execution
 * 
 * @param dbg Pointer to debugger
 * @param thread_id Thread ID or 0 for all threads
 * @return int 0 on success, -1 on failure
 */
int machine_dbg_pause(MachineDebugger* dbg, int thread_id);

/**
 * @brief Get stack trace
 * 
 * @param dbg Pointer to debugger
 * @param thread_id Thread ID
 * @param start_frame Start frame index
 * @param frame_count Number of frames to get
 * @param frames Output array of frames (caller must free)
 * @param total_frames Output total number of frames
 * @return int Number of frames returned, -1 on failure
 */
int machine_dbg_get_stack_trace(MachineDebugger* dbg, int thread_id, int start_frame, 
                               int frame_count, MachineStackFrame** frames, int* total_frames);

/**
 * @brief Get local variables
 * 
 * @param dbg Pointer to debugger
 * @param frame_id Frame ID
 * @param variables Output array of variables (caller must free)
 * @return int Number of variables returned, -1 on failure
 */
int machine_dbg_get_locals(MachineDebugger* dbg, int frame_id, MachineVariable** variables);

/**
 * @brief Get global variables
 * 
 * @param dbg Pointer to debugger
 * @param variables Output array of variables (caller must free)
 * @return int Number of variables returned, -1 on failure
 */
int machine_dbg_get_globals(MachineDebugger* dbg, MachineVariable** variables);

/**
 * @brief Get thread list
 * 
 * @param dbg Pointer to debugger
 * @param threads Output array of threads (caller must free)
 * @return int Number of threads returned, -1 on failure
 */
int machine_dbg_get_threads(MachineDebugger* dbg, MachineThread** threads);

/**
 * @brief Evaluate expression
 * 
 * @param dbg Pointer to debugger
 * @param expression Expression to evaluate
 * @param frame_id Frame ID (context for evaluation)
 * @param thread_id Thread ID (context for evaluation)
 * @param result Output evaluation result (caller must free)
 * @return int 0 on success, -1 on failure
 */
int machine_dbg_evaluate(MachineDebugger* dbg, const char* expression, 
                        int frame_id, int thread_id, MachineVariable** result);

/**
 * @brief Read memory
 * 
 * @param dbg Pointer to debugger
 * @param address Start address
 * @param count Number of bytes to read
 * @param data Output data buffer (caller must allocate)
 * @return int Number of bytes read, -1 on failure
 */
int machine_dbg_read_memory(MachineDebugger* dbg, uint16_t address, int count, uint8_t* data);

/**
 * @brief Write memory
 * 
 * @param dbg Pointer to debugger
 * @param address Start address
 * @param count Number of bytes to write
 * @param data Data to write
 * @return int Number of bytes written, -1 on failure
 */
int machine_dbg_write_memory(MachineDebugger* dbg, uint16_t address, int count, const uint8_t* data);

/**
 * @brief Disassemble code
 * 
 * @param dbg Pointer to debugger
 * @param address Start address
 * @param instruction_count Number of instructions to disassemble
 * @param disassembly Output array of disassembly strings (caller must free)
 * @return int Number of instructions disassembled, -1 on failure
 */
int machine_dbg_disassemble(MachineDebugger* dbg, uint16_t address, 
                           int instruction_count, char** disassembly);

#endif /* ND100X_MACHINE_DBG_H */ 