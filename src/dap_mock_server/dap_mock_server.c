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

// Forward declarations
struct DAPServer;


/*** CALLBACKS ***/

// Function to step the CPU one instruction
static int step_cpu(DAPServer *server) {
    (void)server;
    // Mock implementation to advance PC by 1
    mock_debugger.pc++;
    return mock_debugger.pc;
}

// Function to step the CPU to the next source line
static int step_cpu_line(DAPServer *server) {
    (void)server;
    // Mock implementation to advance PC by 4 (typical instruction size)
    mock_debugger.pc += 4;
    return mock_debugger.pc;
}

// Function to step the CPU to the next statement
static int step_cpu_statement(DAPServer *server) {
    (void)server;
    // Mock implementation to advance PC by 2 (smaller step than line)

    mock_debugger.pc += 2;
    return mock_debugger.pc;
}

/*** INITIALIZATION ***/

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

    mock_debugger.server->step_cpu = step_cpu;
    mock_debugger.server->step_cpu_line = step_cpu_line;
    mock_debugger.server->step_cpu_statement = step_cpu_statement;
    
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