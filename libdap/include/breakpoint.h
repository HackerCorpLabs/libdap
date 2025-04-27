#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "dap_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Register configuration structure
 * 
 * This structure defines how registers are named and mapped in the debugger.
 * It allows for flexible register naming and indexing across different CPU architectures.
 * 
 * @param name    The name of the register (e.g., "PC", "SP")
 * @param index   The index of the register in the registers array
 * @param is_pc   Whether this register is the program counter
 */
typedef struct {
    const char* name;    // Register name (e.g., "PC", "SP")
    int index;          // Register index in the registers array
    bool is_pc;         // Whether this is the program counter
} RegisterConfig;

/**
 * @brief Register definitions
 * 
 * These are the standard register indices used by the debugger.
 * The actual register names and meanings are defined by the RegisterConfig.
 */
typedef enum {
    REG_PC = 0,     // Program Counter (must be first)
    REG_SP,         // Stack Pointer
    REG_A,          // Accumulator
    REG_X,          // X Register
    REG_Y,          // Y Register
    REG_SR,         // Status Register
    REG_COUNT       // Number of registers
} Register;

/**
 * @brief Breakpoint types
 * 
 * Defines the different types of breakpoints supported by the debugger.
 */
typedef enum {
    BREAKPOINT_ADDRESS,          // Break at specific address
    BREAKPOINT_LINE,            // Break at specific source line
    BREAKPOINT_FUNCTION,        // Break at function entry
    BREAKPOINT_MEMORY_READ,     // Break on memory read
    BREAKPOINT_MEMORY_WRITE,    // Break on memory write
    BREAKPOINT_REGISTER_CHANGE, // Break on register change
    BREAKPOINT_CONDITIONAL      // Break when condition is met
} BreakpointType;

/**
 * @brief Condition types
 * 
 * Defines the comparison operators supported in breakpoint conditions.
 * These operators can be used with both register and memory conditions.
 */
typedef enum {
    CONDITION_EQUAL,            // ==
    CONDITION_NOT_EQUAL,        // !=
    CONDITION_LESS,            // <
    CONDITION_LESS_EQUAL,      // <=
    CONDITION_GREATER,         // >
    CONDITION_GREATER_EQUAL,   // >=
    CONDITION_AND,             // &&
    CONDITION_OR,              // ||
    CONDITION_NOT              // !
} ConditionType;

/**
 * @brief Condition structure
 * 
 * Represents a condition that can be evaluated to determine if a breakpoint should trigger.
 * Supports both register and memory conditions using a union.
 */
typedef struct {
    ConditionType type;  // The comparison operator
    union {
        struct {
            uint16_t address;    // Memory address
            uint8_t value;       // Value to compare
        } memory;               // For memory conditions
        struct {
            Register reg;        // Register to check
            uint16_t value;      // Value to compare
        } register_check;       // For register conditions
        struct {
            uint8_t left_type;   // Type of left condition
            uint8_t right_type;  // Type of right condition
            uint16_t left_value; // Value for left condition
            uint16_t right_value; // Value for right condition
        } logical;              // For logical conditions
    } data;
} Condition;

// Breakpoint structure
typedef struct {
    BreakpointType type;
    union {
        uint16_t address;        // For BREAKPOINT_ADDRESS
        struct {
            char file[256];      // Source file
            int line;            // Line number
        } source;                // For BREAKPOINT_LINE
        char function[256];      // For BREAKPOINT_FUNCTION
        struct {
            uint16_t address;    // Memory address
            uint16_t mask;       // Address mask
        } memory;                // For BREAKPOINT_MEMORY_*
        struct {
            Register reg;        // Register to monitor
            uint16_t value;      // Value to match
            uint16_t mask;       // Value mask
        } register_change;       // For BREAKPOINT_REGISTER_CHANGE
        struct {
            Condition condition; // For BREAKPOINT_CONDITIONAL
            char condition_str[256];
        } conditional;
    } location;
    bool enabled;               // Whether breakpoint is enabled
    int hit_count;             // Number of times hit
    int hit_limit;             // Maximum number of hits (0 = unlimited)
} Breakpoint;

// Breakpoint manager structure
typedef struct BreakpointManager BreakpointManager;

/**
 * @brief Create a new breakpoint manager
 * 
 * @param initial_capacity Initial capacity of the breakpoint array
 * @return BreakpointManager* New breakpoint manager, or NULL on error
 */
BreakpointManager* breakpoint_manager_create(size_t initial_capacity);

// Free a breakpoint manager
void breakpoint_manager_free(BreakpointManager* manager);

// Add a breakpoint to the manager
int breakpoint_manager_add(BreakpointManager* manager, const Breakpoint* bp);

// Remove a breakpoint from the manager
int breakpoint_manager_remove(BreakpointManager* manager, int index);

// Get the number of breakpoints
int breakpoint_manager_count(const BreakpointManager* manager);

// Get a breakpoint by index
const Breakpoint* breakpoint_manager_get(const BreakpointManager* manager, int index);

// Set whether a breakpoint is enabled
int breakpoint_manager_set_enabled(BreakpointManager* manager, int index, bool enabled);

// Set the hit limit for a breakpoint
int breakpoint_manager_set_hit_limit(BreakpointManager* manager, int index, int limit);

// Get the hit count for a breakpoint
int breakpoint_manager_get_hit_count(const BreakpointManager* manager, int index);

// Reset the hit count for a breakpoint
int breakpoint_manager_reset_hit_count(BreakpointManager* manager, int index);

// Check if a memory access should trigger a breakpoint
bool breakpoint_manager_check_memory_access(const BreakpointManager* manager,
    uint16_t address, bool is_write);

// Check if a register change should trigger a breakpoint
bool breakpoint_manager_check_register_change(const BreakpointManager* manager,
    Register reg, uint16_t value);

// Check if a condition is met
bool breakpoint_manager_check_condition(const BreakpointManager* manager,
    int index, uint16_t pc, uint16_t* registers, uint8_t* memory);

// Parse a condition string into a Condition structure
bool breakpoint_parse_condition(const char* str, Condition* condition);

// Free a condition structure
void breakpoint_free_condition(Condition* condition);

#ifdef __cplusplus
}
#endif

#endif // BREAKPOINT_H 