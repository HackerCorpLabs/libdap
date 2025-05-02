#ifndef DAP_DEBUGGER_MAIN_H
#define DAP_DEBUGGER_MAIN_H

#include "dap_client.h"
#include "dap_debugger_help.h"

// Forward declarations for command handlers


// Function to print parameter help
int print_parameter_help(const char* command_name);

// Command line processing function
int process_command_line(DAPClient* client, int argc, char* argv[]);

// Main command loop function
int command_loop(DAPClient* client);

#endif // DAP_DEBUGGER_MAIN_H 