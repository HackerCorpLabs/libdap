#include <stdio.h>
#include <stdlib.h>
#include "../include/breakpoint.h"
#include "test_utils.h"
#include <string.h>

static bool test_breakpoint_manager_creation(void) {
    BreakpointManager* manager = breakpoint_manager_create(10);
    TEST_ASSERT(manager != NULL);
    TEST_ASSERT(breakpoint_manager_count(manager) == 0);
    breakpoint_manager_free(manager);
    return true;
}

static void test_line_breakpoint() {
    TEST_START("Line Breakpoint");

    BreakpointManager* manager = breakpoint_manager_create(10);
    TEST_ASSERT(manager != NULL);

    Breakpoint bp = create_line_breakpoint("test.c", 42);
    TEST_ASSERT(breakpoint_manager_add(manager, &bp) >= 0);
    TEST_ASSERT(breakpoint_manager_count(manager) == 1);

    const Breakpoint* stored_bp = breakpoint_manager_get(manager, 0);
    TEST_ASSERT(stored_bp != NULL);
    TEST_ASSERT(stored_bp->type == BREAKPOINT_LINE);
    TEST_ASSERT(strcmp(stored_bp->location.source.file, "test.c") == 0);
    TEST_ASSERT(stored_bp->location.source.line == 42);

    breakpoint_manager_free(manager);
    TEST_END();
}

static void test_memory_breakpoint() {
    TEST_START("Memory Breakpoint");

    BreakpointManager* manager = breakpoint_manager_create(10);
    TEST_ASSERT(manager != NULL);

    Breakpoint bp = create_memory_breakpoint(0x1000, true);
    TEST_ASSERT(breakpoint_manager_add(manager, &bp) >= 0);
    TEST_ASSERT(breakpoint_manager_count(manager) == 1);

    const Breakpoint* stored_bp = breakpoint_manager_get(manager, 0);
    TEST_ASSERT(stored_bp != NULL);
    TEST_ASSERT(stored_bp->type == BREAKPOINT_MEMORY_WRITE);
    TEST_ASSERT(stored_bp->location.memory.address == 0x1000);

    breakpoint_manager_free(manager);
    TEST_END();
}

static void test_register_breakpoint() {
    TEST_START("Register Breakpoint");

    BreakpointManager* manager = breakpoint_manager_create(10);
    TEST_ASSERT(manager != NULL);

    Breakpoint bp = create_register_breakpoint(REG_PC, 0x2000, 0xFFFF);
    TEST_ASSERT(breakpoint_manager_add(manager, &bp) >= 0);
    TEST_ASSERT(breakpoint_manager_count(manager) == 1);

    const Breakpoint* stored_bp = breakpoint_manager_get(manager, 0);
    TEST_ASSERT(stored_bp != NULL);
    TEST_ASSERT(stored_bp->type == BREAKPOINT_REGISTER_CHANGE);
    TEST_ASSERT(stored_bp->location.register_change.reg == REG_PC);
    TEST_ASSERT(stored_bp->location.register_change.value == 0x2000);

    breakpoint_manager_free(manager);
    TEST_END();
}

static void test_breakpoint_enable_disable() {
    TEST_START("Breakpoint Enable/Disable");

    BreakpointManager* manager = breakpoint_manager_create(10);
    TEST_ASSERT(manager != NULL);

    Breakpoint bp = create_memory_breakpoint(0x1000, true);
    int index = breakpoint_manager_add(manager, &bp);
    TEST_ASSERT(index >= 0);

    TEST_ASSERT(breakpoint_manager_set_enabled(manager, index, false) >= 0);
    TEST_ASSERT(breakpoint_manager_get(manager, index)->enabled == false);

    TEST_ASSERT(breakpoint_manager_set_enabled(manager, index, true) >= 0);
    TEST_ASSERT(breakpoint_manager_get(manager, index)->enabled == true);

    breakpoint_manager_free(manager);
    TEST_END();
}

static void test_breakpoint_removal() {
    TEST_START("Breakpoint Removal");

    BreakpointManager* manager = breakpoint_manager_create(10);
    TEST_ASSERT(manager != NULL);

    Breakpoint bp = create_memory_breakpoint(0x1000, true);
    TEST_ASSERT(breakpoint_manager_add(manager, &bp) >= 0);
    TEST_ASSERT(breakpoint_manager_count(manager) == 1);

    TEST_ASSERT(breakpoint_manager_remove(manager, 0) >= 0);
    TEST_ASSERT(breakpoint_manager_count(manager) == 0);

    breakpoint_manager_free(manager);
    TEST_END();
}

static void test_breakpoint_hit_count() {
    TEST_START("Breakpoint Hit Count");

    BreakpointManager* manager = breakpoint_manager_create(10);
    TEST_ASSERT(manager != NULL);

    Breakpoint bp = create_memory_breakpoint(0x1000, true);
    int index = breakpoint_manager_add(manager, &bp);
    TEST_ASSERT(index >= 0);

    TEST_ASSERT(breakpoint_manager_get_hit_count(manager, index) == 0);
    TEST_ASSERT(breakpoint_manager_reset_hit_count(manager, index) >= 0);
    TEST_ASSERT(breakpoint_manager_get_hit_count(manager, index) == 0);

    breakpoint_manager_free(manager);
    TEST_END();
}

static void test_breakpoint_hit_limit() {
    TEST_START("Breakpoint Hit Limit");

    BreakpointManager* manager = breakpoint_manager_create(10);
    TEST_ASSERT(manager != NULL);

    Breakpoint bp = create_memory_breakpoint(0x1000, true);
    int index = breakpoint_manager_add(manager, &bp);
    TEST_ASSERT(index >= 0);

    TEST_ASSERT(breakpoint_manager_set_hit_limit(manager, index, 5) >= 0);
    TEST_ASSERT(breakpoint_manager_get(manager, index)->hit_limit == 5);

    breakpoint_manager_free(manager);
    TEST_END();
}

int main() {
    TEST_RUN(test_breakpoint_manager_creation);
    TEST_RUN(test_line_breakpoint);
    TEST_RUN(test_memory_breakpoint);
    TEST_RUN(test_register_breakpoint);
    TEST_RUN(test_breakpoint_enable_disable);
    TEST_RUN(test_breakpoint_removal);
    TEST_RUN(test_breakpoint_hit_count);
    TEST_RUN(test_breakpoint_hit_limit);
    return 0;
} 