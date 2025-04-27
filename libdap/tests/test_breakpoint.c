#include "breakpoint.h"
#include "dap_error.h"
#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static void test_error_handling() {
    TEST_START("Error Handling");

    // Test invalid capacity
    BreakpointManager* manager = breakpoint_manager_create(0);
    TEST_ASSERT(manager == NULL);
    TEST_ASSERT(dap_get_last_error().code == DAP_ERROR_INVALID_ARG);

    // Test invalid index operations
    manager = breakpoint_manager_create(10);
    TEST_ASSERT(manager != NULL);

    // Test remove with invalid index
    TEST_ASSERT(breakpoint_manager_remove(manager, -1) < 0);
    TEST_ASSERT(dap_get_last_error().code == DAP_ERROR_INVALID_ARG);

    // Test get with invalid index
    TEST_ASSERT(breakpoint_manager_get(manager, 0) == NULL);
    TEST_ASSERT(dap_get_last_error().code == DAP_ERROR_INVALID_ARG);

    // Test set enabled with invalid index
    TEST_ASSERT(breakpoint_manager_set_enabled(manager, 0, true) < 0);
    TEST_ASSERT(dap_get_last_error().code == DAP_ERROR_INVALID_ARG);

    // Test set hit limit with invalid index
    TEST_ASSERT(breakpoint_manager_set_hit_limit(manager, 0, 10) < 0);
    TEST_ASSERT(dap_get_last_error().code == DAP_ERROR_INVALID_ARG);

    // Test get hit count with invalid index
    TEST_ASSERT(breakpoint_manager_get_hit_count(manager, 0) < 0);
    TEST_ASSERT(dap_get_last_error().code == DAP_ERROR_INVALID_ARG);

    // Test reset hit count with invalid index
    TEST_ASSERT(breakpoint_manager_reset_hit_count(manager, 0) < 0);
    TEST_ASSERT(dap_get_last_error().code == DAP_ERROR_INVALID_ARG);

    breakpoint_manager_free(manager);
    TEST_END();
}

static void test_breakpoint_operations(void) {
    TEST_START("Breakpoint Operations");
    
    // Create a breakpoint manager
    BreakpointManager* manager = breakpoint_manager_create(10);
    TEST_ASSERT(manager != NULL);
    
    // Add a line breakpoint
    Breakpoint bp = create_line_breakpoint("test.c", 42);
    int index = breakpoint_manager_add(manager, &bp);
    TEST_ASSERT(index >= 0);
    
    // Get the breakpoint back
    const Breakpoint* stored_bp = breakpoint_manager_get(manager, index);
    TEST_ASSERT(stored_bp != NULL);
    TEST_ASSERT(stored_bp->type == BREAKPOINT_LINE);
    TEST_ASSERT(strcmp(stored_bp->location.source.file, "test.c") == 0);
    TEST_ASSERT(stored_bp->location.source.line == 42);
    
    // Add a conditional breakpoint
    bp = create_conditional_breakpoint("PC == 0x1000");
    index = breakpoint_manager_add(manager, &bp);
    TEST_ASSERT(index >= 0);
    
    // Get the conditional breakpoint back
    stored_bp = breakpoint_manager_get(manager, index);
    TEST_ASSERT(stored_bp != NULL);
    TEST_ASSERT(stored_bp->type == BREAKPOINT_CONDITIONAL);
    TEST_ASSERT(strcmp(stored_bp->location.conditional.condition_str, "PC == 0x1000") == 0);
    
    // Clean up
    breakpoint_manager_free(manager);
    TEST_END();
}

static void test_condition_parsing(void) {
    TEST_START("Condition Parsing");
    
    // Test valid conditions
    Condition cond;
    TEST_ASSERT(breakpoint_parse_condition("PC == 0x1000", &cond));
    TEST_ASSERT(cond.type == CONDITION_EQUAL);
    TEST_ASSERT(cond.data.register_check.reg == REG_PC);
    TEST_ASSERT(cond.data.register_check.value == 0x1000);
    
    TEST_ASSERT(breakpoint_parse_condition("A != 42", &cond));
    TEST_ASSERT(cond.type == CONDITION_NOT_EQUAL);
    TEST_ASSERT(cond.data.register_check.reg == REG_A);
    TEST_ASSERT(cond.data.register_check.value == 42);
    
    TEST_ASSERT(breakpoint_parse_condition("[0x2000] == 0xFF", &cond));
    TEST_ASSERT(cond.type == CONDITION_EQUAL);
    TEST_ASSERT(cond.data.memory.address == 0x2000);
    TEST_ASSERT(cond.data.memory.value == 0xFF);
    
    // Test invalid conditions
    TEST_ASSERT(!breakpoint_parse_condition("INVALID == 0", &cond));
    TEST_ASSERT(!breakpoint_parse_condition("[0x10000] == 0", &cond));  // Invalid address
    TEST_ASSERT(!breakpoint_parse_condition("PC ==", &cond));  // Missing value
    
    TEST_END();
}

static void test_condition_evaluation(void) {
    TEST_START("Condition Evaluation");
    
    // Create a breakpoint manager
    BreakpointManager* manager = breakpoint_manager_create(10);
    TEST_ASSERT(manager != NULL);
    
    // Add a conditional breakpoint
    Breakpoint bp = create_conditional_breakpoint("PC == 0x1000");
    int index = breakpoint_manager_add(manager, &bp);
    TEST_ASSERT(index >= 0);
    
    // Test condition evaluation
    uint16_t registers[REG_COUNT] = {0};
    uint8_t memory[0x10000] = {0};
    
    // PC not equal to 0x1000
    registers[REG_PC] = 0x2000;
    TEST_ASSERT(!breakpoint_manager_check_condition(manager, index, 0x2000, registers, memory));
    
    // PC equal to 0x1000
    registers[REG_PC] = 0x1000;
    TEST_ASSERT(breakpoint_manager_check_condition(manager, index, 0x1000, registers, memory));
    
    // Clean up
    breakpoint_manager_free(manager);
    TEST_END();
}

int main(void) {
    TEST_RUN(test_error_handling);
    TEST_RUN(test_breakpoint_operations);
    TEST_RUN(test_condition_parsing);
    TEST_RUN(test_condition_evaluation);
    return 0;
} 