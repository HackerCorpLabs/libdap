#ifndef DBG_MOCK_H
#define DBG_MOCK_H

#include <stdbool.h>
#include <stdint.h>
#include "../libdap/include/dap_protocol.h"
#include "../libdap/include/dap_types.h"
#include "../libdap/include/dap_server.h"


// Debug logging macro
#define MOCK_SERVER_DEBUG_LOG(...) do { \
    fprintf(stderr, "[DAP SERVER %s:%d] ", __func__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
    fflush(stderr); \
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
void dbg_mock_set_program_path(const char* path);
uint32_t dbg_mock_get_pc(void);
void dbg_mock_set_pc(uint32_t pc);
int dbg_mock_get_current_thread(void);
void dbg_mock_set_current_thread(int thread_id);
bool dbg_mock_is_running(void);
void dbg_mock_set_running(bool running);
bool dbg_mock_is_attached(void);
void dbg_mock_set_attached(bool attached);
int dbg_mock_add_breakpoint(int line, int column);
int dbg_mock_add_breakpoint_with_source(int line, int column, const char* source_path);
int dbg_mock_remove_breakpoint(int line, int column);
bool dbg_mock_has_breakpoint(int line, int column);
int dbg_mock_get_breakpoint_count(void);


DAPBreakpoint* dbg_mock_get_breakpoint(size_t index);





#endif // DBG_MOCK_H 