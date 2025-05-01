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

// Event handling callback
static int handle_event(void* user_data, DAPEventType event, const char* content) {
    MockDebugger* debugger = (MockDebugger*)user_data;
    if (!debugger) {
        return -1;
    }

    debugger->last_event = event;
    const char* event_str = get_event_string(event);
    printf("DEBUG: Received event: %s, content: %s\n", event_str ? event_str : "unknown", content ? content : "NULL");
    return 0;
}


int mock_handle_command(void* user_data, DAPCommandType command,
                             const char* args, DAPResponse* response) {
    (void)user_data;  // Mark as unused
    if (!response) {
        return -1;
    }

    MOCK_SERVER_DEBUG_LOG("Handling command: %d", (int)command);

    // Convert args string to cJSON if needed
    cJSON* json_args = args ? cJSON_Parse(args) : NULL;
    if (args && !json_args) {
        response->success = false;
        response->error_message = strdup("Failed to parse arguments");
        return 0;  // Return 0 even for errors to ensure response is sent
    }

    // Handle different commands
    int result = 0;
    switch (command) {
        case DAP_CMD_INITIALIZE:
            result = handle_initialize(mock_debugger.server, json_args, response);
            break;  
        case DAP_CMD_LAUNCH: {
            MOCK_SERVER_DEBUG_LOG("About to handle launch request");
            result = handle_launch(mock_debugger.server, json_args, response);
            MOCK_SERVER_DEBUG_LOG("Launch request handled, result=%d", result);
            
            // Always return 0 for launch even if there was an error
            // This ensures that the response is sent back to the client
            if (result != 0) {
                MOCK_SERVER_DEBUG_LOG("Converting error result %d to success 0 to ensure response is sent", result);
                result = 0;
            }
            
            // Store a copy of the args for later sending the event
            cJSON* program = json_args ? cJSON_GetObjectItem(json_args, "program") : NULL;
            cJSON* args_array = json_args ? cJSON_GetObjectItem(json_args, "args") : NULL;
            
            // Schedule the event to be sent after response
            if (response->success && program && cJSON_IsString(program)) {
                // Small delay to ensure response is processed first
                usleep(10000); // 10ms delay
                send_launch_stopped_event(mock_debugger.server, program->valuestring, args_array);
            }
            
            break; // Use break instead of return to continue with normal flow
        }
        case DAP_CMD_ATTACH:
            result = handle_attach(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_DISCONNECT:
            cleanup_breakpoints(mock_debugger.server);
            result = handle_disconnect(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_TERMINATE:
            result = handle_terminate(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_RESTART:
            result = handle_restart(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_SET_BREAKPOINTS:
            result = handle_set_breakpoints(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_CONFIGURATION_DONE:
            result = handle_configuration_done(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_THREADS:
            result = handle_threads(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_STACK_TRACE:
            result = handle_stack_trace(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_SCOPES:
            result = handle_scopes(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_VARIABLES:
            result = handle_variables(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_CONTINUE:
            result = handle_continue(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_NEXT:
            result = handle_next(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_STEP_IN:
            result = handle_step_in(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_STEP_OUT:
            result = handle_step_out(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_EVALUATE:
            result = handle_evaluate(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_PAUSE: 
            result = handle_pause(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_READ_MEMORY:
            result = handle_read_memory(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_WRITE_MEMORY:
            result = handle_write_memory(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_READ_REGISTERS:
            result = handle_read_registers(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_WRITE_REGISTERS:
            result = handle_write_register(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_SOURCE:
            result = handle_source(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_LOADED_SOURCES:
            result = handle_loaded_sources(mock_debugger.server, json_args, response);
            break;
        case DAP_CMD_DISASSEMBLE:
            result = handle_disassemble(mock_debugger.server, json_args, response);
            break;        
        default:
            response->success = false;
            response->error_message = strdup("Unknown command");
            result = 0;
            break;
    }

    if (json_args) {
        cJSON_Delete(json_args);
    }
    
    // Ensure we always return 0 so that responses are sent to the client
    // DAP protocol requires all requests to have responses, even errors
    if (result != 0) {
        MOCK_SERVER_DEBUG_LOG("Command handler returned error %d, converting to 0 to ensure response is sent", result);
        result = 0;
    }
    
    return result;
}



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
        .callbacks = {
            .handle_command = mock_handle_command,
            .handle_event = handle_event
        },
        .user_data = &mock_debugger,
        .stop_at_entry = false,
        .program_path = NULL
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
