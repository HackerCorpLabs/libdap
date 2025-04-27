#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include "breakpoint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_START(name) \
    do { \
        printf("Running test: %s\n", name); \
        fflush(stdout); \
    } while (0)

#define TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            printf("Test failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            exit(1); \
        } \
    } while (0)

#define TEST_END() \
    do { \
        printf("Test passed\n\n"); \
        fflush(stdout); \
    } while (0)

#define TEST_RUN(test_func) \
    do { \
        test_func(); \
    } while (0)

// Helper function to create a line breakpoint
static inline Breakpoint create_line_breakpoint(const char* file, int line) {
    Breakpoint bp = {0};  // Zero initialize
    bp.type = BREAKPOINT_LINE;
    bp.enabled = true;
    bp.location.source.line = line;  // Always set the line
    if (file != NULL) {
        strncpy(bp.location.source.file, file, sizeof(bp.location.source.file) - 1);
        bp.location.source.file[sizeof(bp.location.source.file) - 1] = '\0';
    }
    return bp;
}

// Helper function to create a memory breakpoint
static inline Breakpoint create_memory_breakpoint(uint16_t address, bool is_write) {
    Breakpoint bp = {0};  // Zero initialize
    bp.type = is_write ? BREAKPOINT_MEMORY_WRITE : BREAKPOINT_MEMORY_READ;
    bp.location.memory.address = address;
    bp.location.memory.mask = 0xFFFF;
    bp.enabled = true;
    return bp;
}

// Helper function to create a register breakpoint
static inline Breakpoint create_register_breakpoint(Register reg, uint16_t value, uint16_t mask) {
    Breakpoint bp = {0};  // Zero initialize
    bp.type = BREAKPOINT_REGISTER_CHANGE;
    bp.location.register_change.reg = reg;
    bp.location.register_change.value = value;
    bp.location.register_change.mask = mask;
    bp.enabled = true;
    return bp;
}

// Helper function to create a conditional breakpoint
static inline Breakpoint create_conditional_breakpoint(const char* condition_str) {
    Breakpoint bp = {0};  // Zero initialize
    bp.type = BREAKPOINT_CONDITIONAL;
    bp.enabled = true;
    if (condition_str != NULL) {
        strncpy(bp.location.conditional.condition_str, condition_str, 
                sizeof(bp.location.conditional.condition_str) - 1);
        bp.location.conditional.condition_str[sizeof(bp.location.conditional.condition_str) - 1] = '\0';
    }
    return bp;
}

#endif // TEST_UTILS_H 