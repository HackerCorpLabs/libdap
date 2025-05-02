/**
 * @file breakpoint.c
 * @brief Breakpoint handling implementation for the DAP library
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "breakpoint.h"
#include "dap_error.h"
#include <assert.h>
#include <ctype.h>





// Breakpoint manager structure
struct BreakpointManager {
    BreakpointInfo* breakpoints;
    int capacity;
    int count;
};

// Default register configuration for 6502
static const RegisterConfig default_registers[] = {
    {"PC", REG_PC, true},
    {"SP", REG_SP, false},
    {"A",  REG_A,  false},
    {"X",  REG_X,  false},
    {"Y",  REG_Y,  false},
    {"SR", REG_SR, false},
    {NULL, 0, false}  // Terminator
};

/**
 * @brief Create a new breakpoint manager
 * 
 * @param initial_capacity Initial capacity of the breakpoint array
 * @return BreakpointManager* New breakpoint manager, or NULL on error
 */
BreakpointManager* breakpoint_manager_create(size_t initial_capacity) {
    if (initial_capacity == 0) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid initial capacity");
        return NULL;
    }

    BreakpointManager* manager = malloc(sizeof(BreakpointManager));
    if (!manager) {
        dap_error_set(DAP_ERROR_MEMORY, "Failed to allocate breakpoint manager");
        return NULL;
    }

    manager->breakpoints = malloc(initial_capacity * sizeof(BreakpointInfo));
    if (!manager->breakpoints) {
        dap_error_set(DAP_ERROR_MEMORY, "Failed to allocate breakpoint array");
        free(manager);
        return NULL;
    }

    manager->capacity = initial_capacity;
    manager->count = 0;
    dap_error_clear();
    return manager;
}

/**
 * @brief Free a breakpoint manager
 * 
 * @param manager Breakpoint manager to free
 */
void breakpoint_manager_free(BreakpointManager* manager) {
    if (!manager) return;

    if (manager->breakpoints) {
        free(manager->breakpoints);
    }
    free(manager);
    dap_error_clear();
}

/**
 * @brief Resize the breakpoint array
 * 
 * @param manager Breakpoint manager
 * @param new_capacity New capacity
 * @return int 0 on success, -1 on error
 */
static int breakpoint_manager_resize(BreakpointManager* manager, size_t new_capacity) {
    if (!manager || new_capacity == 0) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    BreakpointInfo* new_breakpoints = realloc(manager->breakpoints, 
                                        new_capacity * sizeof(BreakpointInfo));
    if (!new_breakpoints) {
        dap_error_set(DAP_ERROR_MEMORY, "Failed to resize breakpoint array");
        return -1;
    }

    manager->breakpoints = new_breakpoints;
    manager->capacity = new_capacity;
    dap_error_clear();
    return 0;
}

/**
 * @brief Add a breakpoint to the manager
 * 
 * @param manager Breakpoint manager
 * @param bp Breakpoint to add
 * @return int Index of the new breakpoint, or -1 on error
 */
int breakpoint_manager_add(BreakpointManager* manager, const BreakpointInfo* bp) {
    if (!manager || !bp) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    // Resize if needed
    if (manager->count >= manager->capacity) {
        if (breakpoint_manager_resize(manager, manager->capacity * 2) < 0) {
            return -1;
        }
    }

    // Copy the breakpoint
    BreakpointInfo* new_bp = &manager->breakpoints[manager->count];
    new_bp->type = bp->type;
    new_bp->enabled = bp->enabled;
    new_bp->hit_count = bp->hit_count;
    new_bp->hit_limit = bp->hit_limit;
    
    // Copy the appropriate location based on type
    switch (bp->type) {
        case BREAKPOINT_LINE:
            strncpy(new_bp->location.source.file, bp->location.source.file, 
                    sizeof(new_bp->location.source.file) - 1);
            new_bp->location.source.file[sizeof(new_bp->location.source.file) - 1] = '\0';
            new_bp->location.source.line = bp->location.source.line;
            break;
        case BREAKPOINT_FUNCTION:
            strncpy(new_bp->location.function, bp->location.function, 
                    sizeof(new_bp->location.function) - 1);
            new_bp->location.function[sizeof(new_bp->location.function) - 1] = '\0';
            break;
        case BREAKPOINT_CONDITIONAL:
            strncpy(new_bp->location.conditional.condition_str, 
                    bp->location.conditional.condition_str, 
                    sizeof(new_bp->location.conditional.condition_str) - 1);
            new_bp->location.conditional.condition_str[sizeof(new_bp->location.conditional.condition_str) - 1] = '\0';
            // Copy condition
            new_bp->location.conditional.condition = bp->location.conditional.condition;
            break;
        case BREAKPOINT_ADDRESS:
            new_bp->location.memory.address = bp->location.memory.address;
            new_bp->location.memory.mask = bp->location.memory.mask;
            break;
        case BREAKPOINT_MEMORY_READ:
        case BREAKPOINT_MEMORY_WRITE:
            new_bp->location.memory.address = bp->location.memory.address;
            new_bp->location.memory.mask = bp->location.memory.mask;
            break;
        case BREAKPOINT_REGISTER_CHANGE:
            new_bp->location.register_change.reg = bp->location.register_change.reg;
            new_bp->location.register_change.value = bp->location.register_change.value;
            new_bp->location.register_change.mask = bp->location.register_change.mask;
            break;
    }
    
    int index = manager->count;
    manager->count++;
    dap_error_clear();
    return index;
}

/**
 * @brief Remove a breakpoint from the manager
 * 
 * @param manager Breakpoint manager
 * @param index Index of the breakpoint to remove
 * @return int 0 on success, -1 on error
 */
int breakpoint_manager_remove(BreakpointManager* manager, int index) {
    if (!manager || index < 0 || index >= manager->count) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager or index");
        return -1;
    }

    // Free any allocated resources for the breakpoint being removed
    BreakpointInfo* bp = &manager->breakpoints[index];
    if (bp->type == BREAKPOINT_CONDITIONAL) {
        breakpoint_free_condition(&bp->location.conditional.condition);
    }

    // Move the last breakpoint to this position if it's not the last one
    if (index != manager->count - 1) {
        memmove(&manager->breakpoints[index],
                &manager->breakpoints[index + 1],
                sizeof(BreakpointInfo) * (manager->count - index - 1));
    }

    manager->count--;
    dap_error_clear();
    return 0;
}

/**
 * @brief Get the number of breakpoints
 * 
 * @param manager Breakpoint manager
 * @return int Number of breakpoints, or -1 on error
 */
int breakpoint_manager_count(const BreakpointManager* manager) {
    if (!manager) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager");
        return -1;
    }
    dap_error_clear();
    return manager->count;
}

/**
 * @brief Get a breakpoint by index
 * 
 * @param manager Breakpoint manager
 * @param index Index of the breakpoint
 * @return const BreakpointInfo* Breakpoint at the given index, or NULL on error
 */
const BreakpointInfo* breakpoint_manager_get(const BreakpointManager* manager, int index) {
    if (!manager || index < 0 || index >= manager->count) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager or index");
        return NULL;
    }
    dap_error_clear();
    return &manager->breakpoints[index];
}

/**
 * @brief Set whether a breakpoint is enabled
 * 
 * @param manager Breakpoint manager
 * @param index Index of the breakpoint
 * @param enabled Whether the breakpoint should be enabled
 * @return int 0 on success, -1 on error
 */
int breakpoint_manager_set_enabled(BreakpointManager* manager, int index, bool enabled) {
    if (!manager || index < 0 || index >= manager->count) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager or index");
        return -1;
    }
    manager->breakpoints[index].enabled = enabled;
    dap_error_clear();
    return 0;
}

/**
 * @brief Set the hit limit for a breakpoint
 * 
 * @param manager Breakpoint manager
 * @param index Index of the breakpoint
 * @param limit Hit limit (0 = unlimited)
 * @return int 0 on success, -1 on error
 */
int breakpoint_manager_set_hit_limit(BreakpointManager* manager, int index, int limit) {
    if (!manager || index < 0 || index >= manager->count || limit < 0) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager, index, or limit");
        return -1;
    }
    manager->breakpoints[index].hit_limit = limit;
    dap_error_clear();
    return 0;
}

/**
 * @brief Get the hit count for a breakpoint
 * 
 * @param manager Breakpoint manager
 * @param index Index of the breakpoint
 * @return int Hit count, or -1 on error
 */
int breakpoint_manager_get_hit_count(const BreakpointManager* manager, int index) {
    if (!manager || index < 0 || index >= manager->count) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager or index");
        return -1;
    }
    dap_error_clear();
    return manager->breakpoints[index].hit_count;
}

/**
 * @brief Reset the hit count for a breakpoint
 * 
 * @param manager Breakpoint manager
 * @param index Index of the breakpoint
 * @return int 0 on success, -1 on error
 */
int breakpoint_manager_reset_hit_count(BreakpointManager* manager, int index) {
    if (!manager || index < 0 || index >= manager->count) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager or index");
        return -1;
    }
    manager->breakpoints[index].hit_count = 0;
    dap_error_clear();
    return 0;
}

/**
 * @brief Check if a breakpoint has hit its limit
 * 
 * @param bp Breakpoint to check
 * @return true if hit limit reached, false otherwise
 */
static bool check_hit_limit(BreakpointInfo* bp) {
    if (bp->hit_limit > 0 && bp->hit_count >= bp->hit_limit) {
        bp->enabled = false;
        return true;
    }
    return false;
}

/**
 * @brief Check if a memory access should trigger a breakpoint
 * 
 * @param manager Breakpoint manager
 * @param address Memory address
 * @param is_write Whether this is a write access
 * @return true if a breakpoint is triggered, false otherwise
 */
bool breakpoint_manager_check_memory_access(const BreakpointManager* manager,
    uint16_t address, bool is_write) {
    if (!manager) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager");
        return false;
    }

    for (int i = 0; i < manager->count; i++) {
        BreakpointInfo* bp = &manager->breakpoints[i];
        if (!bp->enabled) {
            continue;
        }

        // Match on appropriate breakpoint type
        if ((is_write && bp->type == BREAKPOINT_MEMORY_WRITE) ||
            (!is_write && bp->type == BREAKPOINT_MEMORY_READ)) {
            
            // Check if address matches (with mask)
            if ((address & bp->location.memory.mask) == 
                (bp->location.memory.address & bp->location.memory.mask)) {
                
                bp->hit_count++;
                check_hit_limit(bp);
                dap_error_clear();
                return true;
            }
        }
    }

    dap_error_clear();
    return false;
}

/**
 * @brief Check if a register change should trigger a breakpoint
 * 
 * @param manager Breakpoint manager
 * @param reg Register being changed
 * @param value New register value
 * @return true if a breakpoint is triggered, false otherwise
 */
bool breakpoint_manager_check_register_change(const BreakpointManager* manager,
    RegisterType reg, uint16_t value) {
    if (!manager) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager");
        return false;
    }

    for (int i = 0; i < manager->count; i++) {
        BreakpointInfo* bp = &manager->breakpoints[i];
        if (!bp->enabled || bp->type != BREAKPOINT_REGISTER_CHANGE) {
            continue;
        }

        // Check if register matches
        if (bp->location.register_change.reg == reg) {
            // Check if value matches (with mask)
            if ((value & bp->location.register_change.mask) == 
                (bp->location.register_change.value & bp->location.register_change.mask)) {
                
                bp->hit_count++;
                check_hit_limit(bp);
                dap_error_clear();
                return true;
            }
        }
    }

    dap_error_clear();
    return false;
}

/**
 * @brief Evaluate a condition
 * 
 * @param cond Condition to evaluate
 * @param pc Program counter
 * @param registers Register array
 * @param memory Memory array
 * @return true if condition is met, false otherwise
 */
static bool evaluate_condition(const Condition* cond, uint16_t pc, uint16_t* registers, uint8_t* memory) {
    if (!cond) return false;

    switch (cond->type) {
        case CONDITION_EQUAL:
            if (cond->data.register_check.reg == REG_PC) {
                return pc == cond->data.register_check.value;
            } else {
                return registers[cond->data.register_check.reg] == cond->data.register_check.value;
            }
        case CONDITION_NOT_EQUAL:
            if (cond->data.register_check.reg == REG_PC) {
                return pc != cond->data.register_check.value;
            } else {
                return registers[cond->data.register_check.reg] != cond->data.register_check.value;
            }
        case CONDITION_LESS:
            if (cond->data.register_check.reg == REG_PC) {
                return pc < cond->data.register_check.value;
            } else {
                return registers[cond->data.register_check.reg] < cond->data.register_check.value;
            }
        case CONDITION_LESS_EQUAL:
            if (cond->data.register_check.reg == REG_PC) {
                return pc <= cond->data.register_check.value;
            } else {
                return registers[cond->data.register_check.reg] <= cond->data.register_check.value;
            }
        case CONDITION_GREATER:
            if (cond->data.register_check.reg == REG_PC) {
                return pc > cond->data.register_check.value;
            } else {
                return registers[cond->data.register_check.reg] > cond->data.register_check.value;
            }
        case CONDITION_GREATER_EQUAL:
            if (cond->data.register_check.reg == REG_PC) {
                return pc >= cond->data.register_check.value;
            } else {
                return registers[cond->data.register_check.reg] >= cond->data.register_check.value;
            }
        case CONDITION_AND:
            return cond->data.logical.left && cond->data.logical.right &&
                   evaluate_condition(cond->data.logical.left, pc, registers, memory) &&
                   evaluate_condition(cond->data.logical.right, pc, registers, memory);
        case CONDITION_OR:
            return cond->data.logical.left && cond->data.logical.right &&
                   (evaluate_condition(cond->data.logical.left, pc, registers, memory) ||
                    evaluate_condition(cond->data.logical.right, pc, registers, memory));
        case CONDITION_NOT:
            return cond->data.logical.left &&
                   !evaluate_condition(cond->data.logical.left, pc, registers, memory);
        default:
            return false;
    }
}

/**
 * @brief Check if a conditional breakpoint condition is met
 * 
 * @param manager Breakpoint manager
 * @param index Index of the breakpoint
 * @param pc Program counter
 * @param registers Register array
 * @param memory Memory array
 * @return true if condition is met, false otherwise
 */
bool breakpoint_manager_check_condition(const BreakpointManager* manager,
    int index, uint16_t pc, uint16_t* registers, uint8_t* memory) {
    if (!manager || index < 0 || index >= manager->count || !registers || !memory) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return false;
    }

    const BreakpointInfo* bp = &manager->breakpoints[index];
    if (!bp->enabled || bp->type != BREAKPOINT_CONDITIONAL) {
        dap_error_clear();
        return false;
    }

    bool result = evaluate_condition(&bp->location.conditional.condition, pc, registers, memory);
    dap_error_clear();
    return result;
}

/**
 * @brief Parse a condition string into a Condition structure
 * 
 * @param str Condition string
 * @param condition Condition structure to fill
 * @return true on success, false on error
 */
bool breakpoint_parse_condition(const char* str, Condition* condition) {
    if (!str || !condition) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return false;
    }

    // This is a simplified parser for demonstration
    // In a real implementation, you would parse expressions like "A == 0x10"

    // Skip leading whitespace
    while (*str && isspace(*str)) str++;

    // Check for empty string
    if (!*str) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Empty condition string");
        return false;
    }

    // Look for register name
    RegisterType reg = REG_PC;
    bool found_reg = false;

    // Check each register name
    for (int i = 0; default_registers[i].name; i++) {
        size_t len = strlen(default_registers[i].name);
        if (strncmp(str, default_registers[i].name, len) == 0 && 
            (isspace(str[len]) || str[len] == '=' || str[len] == '!' ||
             str[len] == '<' || str[len] == '>')) {
            
            reg = (RegisterType)default_registers[i].index;
            str += len;
            found_reg = true;
            break;
        }
    }

    if (!found_reg) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid register name in condition");
        return false;
    }

    // Skip whitespace
    while (*str && isspace(*str)) str++;

    // Check for comparison operator
    ConditionType type;
    if (strncmp(str, "==", 2) == 0) {
        type = CONDITION_EQUAL;
        str += 2;
    } else if (strncmp(str, "!=", 2) == 0) {
        type = CONDITION_NOT_EQUAL;
        str += 2;
    } else if (strncmp(str, "<=", 2) == 0) {
        type = CONDITION_LESS_EQUAL;
        str += 2;
    } else if (strncmp(str, ">=", 2) == 0) {
        type = CONDITION_GREATER_EQUAL;
        str += 2;
    } else if (*str == '<') {
        type = CONDITION_LESS;
        str++;
    } else if (*str == '>') {
        type = CONDITION_GREATER;
        str++;
    } else {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid comparison operator in condition");
        return false;
    }

    // Skip whitespace
    while (*str && isspace(*str)) str++;

    // Parse value (hexadecimal or decimal)
    char* endptr;
    uint16_t value;
    if (strncmp(str, "0x", 2) == 0 || strncmp(str, "0X", 2) == 0) {
        value = (uint16_t)strtoul(str, &endptr, 16);
    } else {
        value = (uint16_t)strtoul(str, &endptr, 10);
    }

    if (endptr == str) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid value in condition");
        return false;
    }

    // Set condition
    condition->type = type;
    condition->data.register_check.reg = reg;
    condition->data.register_check.value = value;

    dap_error_clear();
    return true;
}

/**
 * @brief Free a condition structure
 * 
 * @param condition Condition to free
 */
void breakpoint_free_condition(Condition* condition) {
    if (!condition) return;
    
    if (condition->type == CONDITION_AND || condition->type == CONDITION_OR ||
        condition->type == CONDITION_NOT) {
        if (condition->data.logical.left) {
            breakpoint_free_condition(condition->data.logical.left);
            free(condition->data.logical.left);
        }
        if (condition->data.logical.right) {
            breakpoint_free_condition(condition->data.logical.right);
            free(condition->data.logical.right);
        }
    }
}

static void breakpoint_set_string(char* dest, const char* src, size_t max_len) {
    strncpy(dest, src, max_len - 1);
    dest[max_len - 1] = '\0';
}

void breakpoint_set_file(BreakpointInfo* bp, const char* file) {
    if (!bp || !file) return;
    breakpoint_set_string(bp->location.source.file, file, sizeof(bp->location.source.file));
}

void breakpoint_set_function(BreakpointInfo* bp, const char* function) {
    if (!bp || !function) return;
    breakpoint_set_string(bp->location.function, function, sizeof(bp->location.function));
}

void breakpoint_set_condition_str(BreakpointInfo* bp, const char* condition_str) {
    if (!bp || !condition_str) return;
    breakpoint_set_string(bp->location.conditional.condition_str, condition_str, 
                         sizeof(bp->location.conditional.condition_str));
} 