#ifndef DAP_MOCK_SERVER_H
#define DAP_MOCK_SERVER_H

#include <stdbool.h>
#include <stdint.h>
#include "dap_protocol.h"
#include "dap_types.h"
#include "dap_server.h"

#ifdef __cplusplus
extern "C" {
#endif

// Debug logging macro
#define DBG_MOCK_LOG(fmt, ...) \
    do { \
        fprintf(stderr, "[DBG_MOCK] " fmt "\n", ##__VA_ARGS__); \
    } while(0)

// Definition for exception breakpoint filters
typedef struct {
    char* filter_id;          // Filter ID (e.g., "all" or "uncaught")
    bool enabled;             // Whether this filter is enabled
    char* condition;          // Optional condition expression
} ExceptionBreakpointFilter;

/** 
 * @struct MockBreakpoint
 * @brief Structure representing a breakpoint in the mock debugger
 */
typedef struct {
    int id;                  /**< Breakpoint ID */
    bool verified;           /**< Whether the breakpoint is verified */
    char* source_path;       /**< Source file path */
    char* source_name;       /**< Source file name */
    int line;                /**< Line number */
    int column;              /**< Column number (0 if not specified) */
    char* condition;         /**< Condition expression (can be NULL) */
    char* hit_condition;     /**< Hit condition expression (can be NULL) */
    char* log_message;       /**< Log message (can be NULL) */
} MockBreakpoint;

/**
 * @struct MockDebugger
 * @brief Structure for the mock debugger state
 */
typedef struct {
    DAPServer *server;                  /**< DAP server instance */
    
    // Execution state
    uint32_t pc;                        /**< Program counter */
    DAPEventType last_event;            /**< Last event sent */
    bool client_connected;              /**< Whether a client is connected */
    
    // Memory state
    size_t memory_size;                 /**< Size of memory array */
    uint8_t *memory;                    /**< Memory array */
    
    // Register state
    int register_count;                 /**< Number of registers */
    uint16_t *registers;                /**< Register values */
    
    // Breakpoint state
    MockBreakpoint* breakpoints;        /**< Array of breakpoints */
    int breakpoint_count;               /**< Number of breakpoints */
    int breakpoint_capacity;            /**< Capacity of breakpoints array */
    
    // Exception state
    ExceptionBreakpointFilter* exception_filters;  /**< Array of exception filters */
    size_t exception_filter_count;                /**< Number of exception filters */
} MockDebugger;

// Global mock debugger instance
extern MockDebugger mock_debugger;

// Function declarations
int dbg_mock_init(int port);
int dbg_mock_start(void);
void dbg_mock_stop(void);
void dbg_mock_cleanup(void);

/**
 * @brief Set up the default capabilities for the mock server
 * 
 * This function configures which DAP capabilities our mock server
 * actually supports based on our implementation.
 * 
 * @param server The DAP server instance
 * @return int The number of capabilities set
 */
int dbg_mock_set_default_capabilities(DAPServer *server);

/**
 * @brief Simulates a thrown exception and sends an exception stopped event if needed
 * 
 * @param exception_id The ID of the exception (e.g., "NullPointerException")
 * @param description Exception description
 * @param is_uncaught Whether the exception is uncaught
 * @return int 0 if successful, non-zero otherwise
 */
int dbg_mock_throw_exception(const char* exception_id, const char* description, bool is_uncaught);

/**
 * @brief Test function to simulate an exception for testing
 * 
 * @param is_uncaught Whether to simulate an uncaught exception (true) or a caught one (false)
 * @return int 0 on success, non-zero on failure
 */
int dbg_mock_test_exception(bool is_uncaught);

/**
 * @brief Send a test stopped event to simulate stopping at a specific line
 * 
 * @param line Line number to stop at
 * @param file File path (or NULL to use current)
 * @return int 0 if successful, non-zero otherwise 
 */
int dbg_mock_test_stop_at_line(int line, const char* file);

/**
 * @brief Send demo output messages showing all output categories
 * 
 * This function demonstrates all available output categories by sending
 * example messages for each one.
 * 
 * @param server The DAP server instance
 */
void dbg_mock_send_demo_outputs(DAPServer *server);

/**
 * @brief Send launch-related output messages
 * 
 * This function sends output messages after a program is launched,
 * demonstrating the different output categories.
 * 
 * @param server The DAP server instance
 * @param program_path The path to the launched program
 */
void dbg_mock_show_launch_messages(DAPServer *server, const char *program_path);

/**
 * @brief Check if a breakpoint is hit at the specified location
 * 
 * @param address Memory address
 * @param source_path Source file path (optional)
 * @param line Line number
 * @return int Breakpoint ID if hit, 0 if no breakpoint
 */
int dbg_mock_is_breakpoint_hit(uint32_t address, const char* source_path, int line);

/**
 * @brief Trigger a breakpoint hit event
 * 
 * @param breakpoint_id ID of the breakpoint hit
 * @return int 0 on success, non-zero on failure
 */
int dbg_mock_trigger_breakpoint_hit(int breakpoint_id);

#ifdef __cplusplus
}
#endif

#endif // DAP_MOCK_SERVER_H 