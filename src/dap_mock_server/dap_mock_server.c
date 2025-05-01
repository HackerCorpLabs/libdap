/*
 * Copyright (c) 2025 Ronny Hansen
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>  // Added for va_list
#include <ctype.h>   // Added for isdigit() and other character classification functions
#include <cjson/cJSON.h>
#include "../libdap/include/dap_server.h"
#include "../libdap/include/dap_error.h"
#include "../libdap/include/dap_types.h"
#include "../libdap/include/dap_transport.h"
#include "../libdap/include/dap_protocol.h"
#include <sys/stat.h>

#include "dap_mock_server.h"
#include "dap_mock_server_commands.h"





// Forward declarations
struct DAPServer;


// Update the line_maps field in MockDebugger initialization
MockDebugger mock_debugger = {
    .server = NULL,
    .pc = 0,
    .last_event = DAP_EVENT_INVALID,
    .memory_size = 0,
    .memory = NULL,
    .register_count = 0,
    .registers = NULL
};

int dbg_mock_init(int port) {
    // Initialize mock debugger state
    mock_debugger.pc = 0;
    mock_debugger.last_event = DAP_EVENT_INVALID;
    mock_debugger.memory_size = 0;
    mock_debugger.memory = NULL;
    mock_debugger.register_count = 0;
    mock_debugger.registers = NULL;

    // Initialize DAP server
    DAPServerConfig config = {
        .transport = {
            .type = DAP_TRANSPORT_TCP,
            .config = {
                .tcp = {
                    .host = "localhost",
                    .port = port
                }
            }
        },           
        .stop_at_entry = false,        
    };

    mock_debugger.server = dap_server_create(&config);
    if (!mock_debugger.server) {
        return -1;
    }

    return 0;
}

int dbg_mock_start(void) {
    if (!mock_debugger.server) {
        return -1;
    }

    return dap_server_start(mock_debugger.server);
}

void dbg_mock_stop(void) {
    if (mock_debugger.server) {
        dap_server_stop(mock_debugger.server);
    }
}

void dbg_mock_cleanup(void) {

    
    // Free memory, if allocated
    if (mock_debugger.memory) {
        free(mock_debugger.memory);
        mock_debugger.memory = NULL;
    }
    
    // Free registers, if allocated
    if (mock_debugger.registers) {
        free(mock_debugger.registers);
        mock_debugger.registers = NULL;
    }
    
    // Stop and free the server
    if (mock_debugger.server) {
        dap_server_stop(mock_debugger.server);
        dap_server_free(mock_debugger.server);
        mock_debugger.server = NULL;
    }
}

void dbg_mock_set_program_path(const char* path) {
    if (mock_debugger.server->program_path) {
        free((void*)mock_debugger.server->program_path);
    }
    mock_debugger.server->program_path = path ? strdup(path) : NULL;
}

uint32_t dbg_mock_get_pc(void) {
    return mock_debugger.pc;
}

void dbg_mock_set_pc(uint32_t pc) {
    mock_debugger.pc = pc;
}

int dbg_mock_get_current_thread(void) {
    return mock_debugger.server->current_thread;
}

void dbg_mock_set_current_thread(int thread_id) {
    mock_debugger.server->current_thread = thread_id;
}

bool dbg_mock_is_running(void) {
    return mock_debugger.server->running;
}

void dbg_mock_set_running(bool running) {
    mock_debugger.server->running = running;
}

bool dbg_mock_is_attached(void) {
    return mock_debugger.server->attached;
}

void dbg_mock_set_attached(bool attached) {
    mock_debugger.server->attached = attached;
}





int handle_disconnect(DAPServer* server, cJSON* args, DAPResponse* response) {
    (void)server;  // Mark as unused
    (void)args;  // Mark as unused

    printf("Disconnecting from debuggee\n");
    
    response->success = true;
    response->data = strdup("{}");
    return 0;
}

int handle_terminate(DAPServer* server, cJSON* args, DAPResponse* response) {
    (void)server;  // Mark as unused
    (void)args;  // Mark as unused

    printf("Terminating debuggee\n");
    
    response->success = true;
    response->data = strdup("{}");
    return 0;
}


int handle_restart(DAPServer* server, cJSON* args, DAPResponse* response) {
    (void)server;  // Mark as unused
    (void)args;  // Mark as unused

    printf("Restarting debuggee\n");
    
    response->success = true;
    response->data = strdup("{}");
    return 0;
}
