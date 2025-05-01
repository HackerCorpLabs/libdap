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
    Breakpoint* breakpoints;
    int capacity;
    int count;
};

// Simplified condition structure
struct Condition {
    ConditionType type;
    union {
        struct {
            Register reg;
            uint16_t value;
        } register_check;
        struct {
            uint16_t address;
            uint8_t value;
        } memory;
        struct {
            Condition* left;
            Condition* right;
        } logical;
    } data;
};

// Breakpoint structure with embedded strings
struct Breakpoint {
    BreakpointType type;
    bool enabled;
    int hit_count;
    int hit_limit;
    union {
        struct {
            char file[256];  // Fixed size for simplicity
            int line;
        } source;
        struct {
            char function[256];  // Fixed size for simplicity
        } function;
        struct {
            uint16_t address;
            uint16_t mask;
        } memory;
        struct {
            Register reg;
            uint16_t value;
            uint16_t mask;
        } register_change;
        struct {
            Condition condition;  // Embedded condition, not a pointer
            char condition_str[256];  // Fixed size for simplicity
        } conditional;
    } location;
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

    manager->breakpoints = malloc(initial_capacity * sizeof(Breakpoint));
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

    Breakpoint* new_breakpoints = realloc(manager->breakpoints, 
                                        new_capacity * sizeof(Breakpoint));
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
int breakpoint_manager_add(BreakpointManager* manager, const Breakpoint* bp) {
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
    Breakpoint* new_bp = &manager->breakpoints[manager->count];
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
            
            // Parse the condition string into the embedded condition struct
            if (!breakpoint_parse_condition(new_bp->location.conditional.condition_str, 
                                         &new_bp->location.conditional.condition)) {
                dap_error_set(DAP_ERROR_INVALID_ARG, "Failed to parse condition");
                return -1;
            }
            break;
        case BREAKPOINT_ADDRESS:
            new_bp->location.address = bp->location.address;
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
        default:
            dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid breakpoint type");
            return -1;
    }

    manager->count++;
    dap_error_clear();
    return manager->count - 1;
}

int breakpoint_manager_remove(BreakpointManager* manager, int index) {
    if (!manager || index < 0 || index >= manager->count) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager or index");
        return -1;
    }

    // Free any allocated resources for the breakpoint being removed
    Breakpoint* bp = &manager->breakpoints[index];
    if (bp->type == BREAKPOINT_CONDITIONAL) {
        breakpoint_free_condition(&bp->location.conditional.condition);
    }

    // Shift remaining breakpoints
    if (index < manager->count - 1) {
        memmove(&manager->breakpoints[index],
                &manager->breakpoints[index + 1],
                sizeof(Breakpoint) * (manager->count - index - 1));
    }

    manager->count--;
    dap_error_clear();
    return 0;
}

int breakpoint_manager_count(const BreakpointManager* manager) {
    if (!manager) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager");
        return -1;
    }
    dap_error_clear();
    return manager->count;
}

const Breakpoint* breakpoint_manager_get(const BreakpointManager* manager, int index) {
    if (!manager || index < 0 || index >= manager->count) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager or index");
        return NULL;
    }
    dap_error_clear();
    return &manager->breakpoints[index];
}

int breakpoint_manager_set_enabled(BreakpointManager* manager, int index, bool enabled) {
    if (!manager || index < 0 || index >= manager->count) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager or index");
        return -1;
    }
    manager->breakpoints[index].enabled = enabled;
    dap_error_clear();
    return 0;
}

int breakpoint_manager_set_hit_limit(BreakpointManager* manager, int index, int limit) {
    if (!manager || index < 0 || index >= manager->count) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager or index");
        return -1;
    }
    manager->breakpoints[index].hit_limit = limit;
    dap_error_clear();
    return 0;
}

int breakpoint_manager_get_hit_count(const BreakpointManager* manager, int index) {
    if (!manager || index < 0 || index >= manager->count) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager or index");
        return -1;
    }
    dap_error_clear();
    return manager->breakpoints[index].hit_count;
}

int breakpoint_manager_reset_hit_count(BreakpointManager* manager, int index) {
    if (!manager || index < 0 || index >= manager->count) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager or index");
        return -1;
    }
    manager->breakpoints[index].hit_count = 0;
    dap_error_clear();
    return 0;
}

static bool check_hit_limit(Breakpoint* bp) {
    if (bp->hit_limit > 0 && bp->hit_count >= bp->hit_limit) {
        bp->enabled = false;
        return false;
    }
    bp->hit_count++;
    return true;
}

bool breakpoint_manager_check_memory_access(const BreakpointManager* manager,
    uint16_t address, bool is_write) {
    if (!manager) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager");
        return false;
    }

    for (int i = 0; i < manager->count; i++) {
        Breakpoint* bp = &manager->breakpoints[i];
        if (!bp->enabled) {
            continue;
        }

        if ((is_write && bp->type == BREAKPOINT_MEMORY_WRITE) ||
            (!is_write && bp->type == BREAKPOINT_MEMORY_READ)) {
            if ((address & bp->location.memory.mask) == bp->location.memory.address) {
                return check_hit_limit(bp);
            }
        }
    }

    dap_error_clear();
    return false;
}

bool breakpoint_manager_check_register_change(const BreakpointManager* manager,
    Register reg, uint16_t value) {
    if (!manager) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager");
        return false;
    }

    for (int i = 0; i < manager->count; i++) {
        Breakpoint* bp = &manager->breakpoints[i];
        if (!bp->enabled || bp->type != BREAKPOINT_REGISTER_CHANGE) {
            continue;
        }

        if (bp->location.register_change.reg == reg) {
            if ((value & bp->location.register_change.mask) == bp->location.register_change.value) {
                return check_hit_limit(bp);
            }
        }
    }

    dap_error_clear();
    return false;
}

// Helper function to evaluate a condition
static bool evaluate_condition(const Condition* cond, uint16_t pc, uint16_t* registers, uint8_t* memory) {
    if (!cond) return false;

    // Check if this is a memory condition
    if (cond->data.memory.address != 0 || cond->data.memory.value != 0) {
        if (!memory) return false;
        uint8_t mem_value = memory[cond->data.memory.address];
        
        switch (cond->type) {
            case CONDITION_EQUAL:
                return mem_value == cond->data.memory.value;
            case CONDITION_NOT_EQUAL:
                return mem_value != cond->data.memory.value;
            case CONDITION_LESS:
                return mem_value < cond->data.memory.value;
            case CONDITION_LESS_EQUAL:
                return mem_value <= cond->data.memory.value;
            case CONDITION_GREATER:
                return mem_value > cond->data.memory.value;
            case CONDITION_GREATER_EQUAL:
                return mem_value >= cond->data.memory.value;
            default:
                return false;
        }
    }

    // Handle register conditions
    switch (cond->type) {
        case CONDITION_EQUAL:
            if (cond->data.register_check.reg == REG_PC) {
                return pc == cond->data.register_check.value;
            }
            return registers[cond->data.register_check.reg] == cond->data.register_check.value;

        case CONDITION_NOT_EQUAL:
            if (cond->data.register_check.reg == REG_PC) {
                return pc != cond->data.register_check.value;
            }
            return registers[cond->data.register_check.reg] != cond->data.register_check.value;

        case CONDITION_LESS:
            if (cond->data.register_check.reg == REG_PC) {
                return pc < cond->data.register_check.value;
            }
            return registers[cond->data.register_check.reg] < cond->data.register_check.value;

        case CONDITION_LESS_EQUAL:
            if (cond->data.register_check.reg == REG_PC) {
                return pc <= cond->data.register_check.value;
            }
            return registers[cond->data.register_check.reg] <= cond->data.register_check.value;

        case CONDITION_GREATER:
            if (cond->data.register_check.reg == REG_PC) {
                return pc > cond->data.register_check.value;
            }
            return registers[cond->data.register_check.reg] > cond->data.register_check.value;

        case CONDITION_GREATER_EQUAL:
            if (cond->data.register_check.reg == REG_PC) {
                return pc >= cond->data.register_check.value;
            }
            return registers[cond->data.register_check.reg] >= cond->data.register_check.value;

        default:
            return false;
    }
}

// Check if a condition is met
bool breakpoint_manager_check_condition(const BreakpointManager* manager,
    int index, uint16_t pc, uint16_t* registers, uint8_t* memory) {
    if (!manager || index < 0 || index >= manager->count) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid manager or index");
        return false;
    }

    const Breakpoint* bp = &manager->breakpoints[index];
    if (!bp->enabled || bp->type != BREAKPOINT_CONDITIONAL) {
        dap_error_clear();
        return false;
    }

    bool result = evaluate_condition(&bp->location.conditional.condition, pc, registers, memory);
    dap_error_clear();
    return result;
}

// Parse a condition string into a Condition structure
bool breakpoint_parse_condition(const char* str, Condition* condition) {
    if (!str || !condition) return false;

    // Initialize the condition
    memset(condition, 0, sizeof(Condition));

    // Skip whitespace
    while (isspace(*str)) str++;

    // Check if this is a memory condition
    if (*str == '[') {
        str++;  // Skip '['
        
        // Parse address
        char* end;
        unsigned long address = strtoul(str, &end, 0);
        if (end == str) return false;
        str = end;
        
        // Validate address is within 16-bit range
        if (address > 0xFFFF) return false;
        condition->data.memory.address = (uint16_t)address;
        
        // Skip ']'
        while (isspace(*str)) str++;
        if (*str != ']') return false;
        str++;
        
        // Skip whitespace
        while (isspace(*str)) str++;
        
        // Parse operator
        if (strncmp(str, "==", 2) == 0) {
            condition->type = CONDITION_EQUAL;
            str += 2;
        } else if (strncmp(str, "!=", 2) == 0) {
            condition->type = CONDITION_NOT_EQUAL;
            str += 2;
        } else {
            return false;
        }
        
        // Skip whitespace
        while (isspace(*str)) str++;
        
        // Parse value
        unsigned long value = strtoul(str, &end, 0);
        if (end == str) return false;
        
        // Validate value is within 8-bit range
        if (value > 0xFF) return false;
        condition->data.memory.value = (uint8_t)value;
        
        return true;
    }
    
    // Parse register condition
    const RegisterConfig* reg = default_registers;
    while (reg->name) {
        size_t len = strlen(reg->name);
        if (strncmp(str, reg->name, len) == 0) {
            condition->data.register_check.reg = reg->index;
            str += len;
            break;
        }
        reg++;
    }
    
    if (!reg->name) return false;  // No matching register found

    // Skip whitespace
    while (isspace(*str)) str++;

    // Parse operator
    if (strncmp(str, "==", 2) == 0) {
        condition->type = CONDITION_EQUAL;
        str += 2;
    } else if (strncmp(str, "!=", 2) == 0) {
        condition->type = CONDITION_NOT_EQUAL;
        str += 2;
    } else if (strncmp(str, "<", 1) == 0) {
        condition->type = CONDITION_LESS;
        str += 1;
    } else if (strncmp(str, "<=", 2) == 0) {
        condition->type = CONDITION_LESS_EQUAL;
        str += 2;
    } else if (strncmp(str, ">", 1) == 0) {
        condition->type = CONDITION_GREATER;
        str += 1;
    } else if (strncmp(str, ">=", 2) == 0) {
        condition->type = CONDITION_GREATER_EQUAL;
        str += 2;
    } else {
        return false;
    }

    // Skip whitespace
    while (isspace(*str)) str++;

    // Parse value
    char* end;
    condition->data.register_check.value = strtoul(str, &end, 0);
    if (end == str) return false;

    return true;
}

// Free a condition structure (now just clears it)
void breakpoint_free_condition(Condition* condition) {
    if (!condition) return;
    memset(condition, 0, sizeof(Condition));
}

// Helper function to safely set a string field with length checking
static void breakpoint_set_string(char* dest, const char* src, size_t max_len) {
    if (!dest || !src) return;
    strncpy(dest, src, max_len - 1);
    dest[max_len - 1] = '\0';
}

// Helper function to safely set file name
void breakpoint_set_file(Breakpoint* bp, const char* file) {
    if (!bp || !file) return;
    breakpoint_set_string(bp->location.source.file, file, sizeof(bp->location.source.file));
}

// Helper function to safely set function name
void breakpoint_set_function(Breakpoint* bp, const char* function) {
    if (!bp || !function) return;
    breakpoint_set_string(bp->location.function, function, sizeof(bp->location.function));
}

// Helper function to safely set condition string
void breakpoint_set_condition_str(Breakpoint* bp, const char* condition_str) {
    if (!bp || !condition_str) return;
    breakpoint_set_string(bp->location.conditional.condition_str, condition_str, 
                         sizeof(bp->location.conditional.condition_str));
} 