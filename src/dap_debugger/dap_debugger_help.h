#ifndef DAP_DEBUGGER_HELP_H
#define DAP_DEBUGGER_HELP_H

#include <stdbool.h>
#include <stdint.h>
#include "../libdap/include/dap_client.h"
#include "dap_debugger_types.h"

extern const DebuggerCommand commands[];

// Helper function to create a string of repeated characters
char* str_repeat(char c, int count);

// Convert category enum to text
const char* category_to_text(CommandCategory category);

// Print shell help
void print_shell_help(void);

// Find command by name
const DebuggerCommand* find_command(const char* name);

// Print detailed help for a command
void print_command_help(const char* command_name);

// Command handler for help command
int handle_help_command(DAPClient* client, const char* args);

#endif // DAP_DEBUGGER_HELP_H 