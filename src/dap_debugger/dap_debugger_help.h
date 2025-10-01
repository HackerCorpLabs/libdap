#ifndef DAP_DEBUGGER_HELP_H
#define DAP_DEBUGGER_HELP_H

#include <stdbool.h>
#include <stdint.h>
#include "dap_client.h"
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

// Print unsupported commands
void print_unsupported_commands(void);

// Command handler for help command
int handle_help_command(DAPClient* client, const char* args);

/**
 * @brief Display help for all commands or a specific command
 * 
 * @param client DAP client
 * @param command_name Command name to display help for, or NULL for all commands
 * @return int 0 on success, non-zero on error
 */
int display_help(DAPClient* client, const char* command_name);

/**
 * @brief Register all command help entries
 * 
 * This function registers all help entries for supported commands
 * 
 * @return int 0 on success, non-zero on error
 */
int register_command_help(void);

/**
 * @brief Clean up help system resources
 * 
 * @return int 0 on success, non-zero on error
 */
int cleanup_help_system(void);

#endif // DAP_DEBUGGER_HELP_H 