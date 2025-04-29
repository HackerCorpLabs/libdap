/**
 * @file dap_mock_server_commands.h
 * @brief Command handler declarations for the DAP mock server
 */

#ifndef DAP_MOCK_SERVER_COMMANDS_H
#define DAP_MOCK_SERVER_COMMANDS_H

#include <cjson/cJSON.h>
#include "../libdap/include/dap_protocol.h"


int handle_execution_control(DAPCommandType command, cJSON* args, DAPResponse* response);


// Command handler declarations
int handle_initialize(cJSON* args, DAPResponse* response);
int handle_launch(cJSON* args, DAPResponse* response);
int handle_attach(cJSON* args, DAPResponse* response);
int handle_disconnect(cJSON* args, DAPResponse* response);
int handle_terminate(cJSON* args, DAPResponse* response);
int handle_restart(cJSON* args, DAPResponse* response);
int handle_set_breakpoints(cJSON* args, DAPResponse* response);
int handle_source(cJSON* args, DAPResponse* response);
int handle_threads(cJSON* args, DAPResponse* response);
int handle_stack_trace(cJSON* args, DAPResponse* response);
int handle_disassemble(cJSON* args, DAPResponse* response);
int handle_loaded_sources(cJSON* args, DAPResponse* response);
int handle_break(cJSON* args, DAPResponse* response);
int handle_scopes(cJSON* args, DAPResponse* response);
int handle_variables(cJSON* args, DAPResponse* response);
int handle_continue(cJSON* args, DAPResponse* response);
int handle_next(cJSON* args, DAPResponse* response);
int handle_step_in(cJSON* args, DAPResponse* response);
int handle_step_out(cJSON* args, DAPResponse* response);
int handle_evaluate(cJSON* args, DAPResponse* response);
int handle_configuration_done(cJSON* args, DAPResponse* response);
int handle_read_memory(cJSON* args, DAPResponse* response);
int handle_write_memory(cJSON* args, DAPResponse* response);
int handle_read_registers(cJSON* args, DAPResponse* response);
int handle_write_register(cJSON* args, DAPResponse* response);
int handle_pause(cJSON* args, DAPResponse* response);

// Callback function for handling DAP commands
int mock_handle_command(void* user_data, DAPCommandType command, const char* args, DAPResponse* response);

#endif // DAP_MOCK_SERVER_COMMANDS_H