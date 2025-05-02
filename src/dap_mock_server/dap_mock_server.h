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

// Mock debugger state structure
typedef struct {
    DAPServer* server;
    uint32_t pc;    
    DAPEventType last_event;
    size_t memory_size;
    uint8_t* memory;
    size_t register_count;
    uint32_t* registers;
} MockDebugger;

// Global mock debugger instance
extern MockDebugger mock_debugger;

// Function declarations
int dbg_mock_init(int port);
int dbg_mock_start(void);
void dbg_mock_stop(void);
void dbg_mock_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // DAP_MOCK_SERVER_H 