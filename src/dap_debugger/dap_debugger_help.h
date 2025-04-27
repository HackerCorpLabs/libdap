#ifndef DAP_DEBUGGER_HELP_H
#define DAP_DEBUGGER_HELP_H

#include <stdbool.h>

// Command detailed help structure
typedef struct {
    const char* command_name;
    const char* syntax;
    const char* description;
    const char* request_format;
    const char* response_format;
    const char* events;
    const char* example;
} CommandHelpInfo;

// Command categories
typedef enum {
    CATEGORY_PROGRAM_CONTROL,
    CATEGORY_EXECUTION_CONTROL,
    CATEGORY_BREAKPOINTS,
    CATEGORY_STACK_AND_VARIABLES,
    CATEGORY_SOURCE,
    CATEGORY_THREADS,
    CATEGORY_EVALUATION,
    CATEGORY_MEMORY,
    CATEGORY_DISASSEMBLY,
    CATEGORY_REGISTERS,
    CATEGORY_OTHER,
    CATEGORY_COUNT
} CommandCategory;

// Command completion structure
typedef struct {
    const char* name;
    const char* alias;
    const char* description;
    CommandCategory category;
    bool implemented;
    bool has_options;
    const char* option_types;
    const char* option_descriptions;
} CommandInfo;

extern const CommandHelpInfo command_help[];
extern const CommandInfo commands[];

const char* category_to_text(CommandCategory category);
void print_shell_help(void);
char* str_repeat(char c, int count);

#endif // DAP_DEBUGGER_HELP_H 