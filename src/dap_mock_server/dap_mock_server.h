#ifndef DBG_MOCK_H
#define DBG_MOCK_H

#include <stdbool.h>
#include <stdint.h>
#include "../libdap/include/dap_protocol.h"
#include "../libdap/include/dap_types.h"
#include "../libdap/include/dap_server.h"

// Line mapping structure
typedef struct {
    const char* file_path;
    int line;
    uint32_t address;
} SourceLineMap;

// Mock debugger state structure
typedef struct {
    DAPServer* server;
    bool running;
    bool attached;
    bool paused;
    const char* program_path;
    int current_thread;
    uint32_t pc;
    int breakpoint_count;
    DAPBreakpoint* breakpoints;
    const DAPSource* current_source;
    int current_line;
    int current_column;
    DAPEventType last_event;
    size_t memory_size;
    uint8_t* memory;
    size_t register_count;
    uint32_t* registers;
    // Line mapping fields
    SourceLineMap* line_maps;
    int line_map_count;
    int line_map_capacity;
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
int dbg_mock_remove_breakpoint(int line, int column);
bool dbg_mock_has_breakpoint(int line, int column);
int dbg_mock_get_breakpoint_count(void);
DAPBreakpoint* dbg_mock_get_breakpoint(size_t index);

// Command handler declarations
int handle_pause(cJSON* args, DAPResponse* response);

#endif // DBG_MOCK_H 