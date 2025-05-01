#include "dap_server.h"
#include <cjson/cJSON.h>


// Command handler declarations

int handle_disconnect(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_terminate(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_restart(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_set_breakpoints(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_source(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_threads(DAPServer* server,   cJSON* args, DAPResponse* response);
int handle_stack_trace(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_disassemble(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_loaded_sources(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_break(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_scopes(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_variables(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_continue(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_next(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_step_in(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_step_out(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_evaluate(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_configuration_done(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_read_memory(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_write_memory(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_read_registers(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_write_register(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_pause(DAPServer* server, cJSON* args, DAPResponse* response);



// Callback function for handling DAP commands
int handle_launch(DAPServer* server, cJSON* args, DAPResponse* response) ;
int handle_attach(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_initialize(DAPServer* server, cJSON* args, DAPResponse* response);


int handle_execution_control(DAPServer* server, DAPCommandType command, cJSON* args, DAPResponse* response);