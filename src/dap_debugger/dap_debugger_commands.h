#ifndef DAP_DEBUGGER_COMMANDS_H
#define DAP_DEBUGGER_COMMANDS_H

#include "dap_client.h"

// Command handler function declarations
int handle_help_command(DAPClient* client, const char* args);
int handle_quit_command(DAPClient* client, const char* args);
int handle_break_command(DAPClient* client, const char* args);
int handle_source_command(DAPClient* client, const char* args);
int handle_continue_command(DAPClient* client, const char* args);
int handle_step_command(DAPClient* client, const char* args);
int handle_step_out_command(DAPClient* client, const char* args);
int handle_next_command(DAPClient* client, const char* args);
int handle_read_memory_command(DAPClient* client, const char* args);
int handle_write_memory_command(DAPClient* client, const char* args);
int handle_disassemble_command(DAPClient* client, const char* args);
int handle_stackTrace_command(DAPClient* client, const char* args);
int handle_frame_command(DAPClient* client, const char* args);
int handle_variables_command(DAPClient* client, const char* args);
int handle_exception_command(DAPClient* client, const char* args);
/**
 * @brief Print variables with proper formatting based on type and nested structure
 * 
 * @param client DAP client
 * @param variables Array of variables to print
 * @param num_variables Number of variables
 * @param indent Current indentation level
 * @param max_depth Maximum recursion depth
 * @return int 0 on success, non-zero on error
 */
int print_variables(DAPClient* client, DAPVariable* variables, size_t num_variables, int indent, int max_depth);
int handle_evaluate_command(DAPClient* client, const char* args);
int handle_set_command(DAPClient* client, const char* args);
int handle_attach_command(DAPClient* client, const char* args);
int handle_detach_command(DAPClient* client, const char* args);
int handle_kill_command(DAPClient* client, const char* args);
int handle_restart_command(DAPClient* client, const char* args);
int handle_set_option_command(DAPClient* client, const char* args);
int handle_show_options_command(DAPClient* client, const char* args);
int handle_source_command(DAPClient* client, const char* args);
int handle_search_command(DAPClient* client, const char* args);
int handle_shell_command(DAPClient* client, const char* args);
int handle_threads_command(DAPClient* client, const char* args);
int handle_scopes_command(DAPClient* client, const char* args);
int handle_debugmode_command(DAPClient* client, const char* args);
int handle_pause_command(DAPClient* client, const char* args);
int handle_launch_command(DAPClient* client, const char* args);
int handle_capabilities_command(DAPClient* client, const char* args);

#endif // DAP_DEBUGGER_COMMANDS_H 