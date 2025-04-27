#ifndef DAP_DEBUGGER_UI_H
#define DAP_DEBUGGER_UI_H

void print_usage(const char* program_name);
void print_command_with_cursor(const char* cmd, int cursor_pos);
void handle_tab_completion(char* cmd, int* cursor_pos);

#endif // DAP_DEBUGGER_UI_H 