/**
 * @file dap_debugger.h
 * @brief Debug Adapter Protocol debugger interface definitions
 */

#ifndef DAP_DEBUGGER_H
#define DAP_DEBUGGER_H

#include "dap_server.h"
#include "dap_types.h"
#include "dap_protocol.h"

// Debugger state structure
typedef struct {
    DAPServer* server;
    bool running;
    bool attached;
    char* program_path;
    int current_thread;
    uint32_t pc;
    int breakpoint_count;
    DAPBreakpoint* breakpoints;
} DAPDebugger;

#endif // DAP_DEBUGGER_H 