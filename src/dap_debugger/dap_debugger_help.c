
#include "dap_debugger_types.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern const DebuggerCommand commands[];

// Helper function to create a string of repeated characters
char* str_repeat(char c, int count) {
    char* buffer = malloc(count + 1);
    if (buffer) {
        memset(buffer, c, count);
        buffer[count] = '\0';
    }
    return buffer;
}

const char* category_to_text(CommandCategory category) {
    switch (category) {
        case CATEGORY_PROGRAM_CONTROL: return "Program Control";
        case CATEGORY_EXECUTION_CONTROL: return "Execution Control";
        case CATEGORY_BREAKPOINTS: return "Breakpoints";
        case CATEGORY_STACK_AND_VARIABLES: return "Stack and Variables";
        case CATEGORY_SOURCE: return "Source";
        case CATEGORY_THREADS: return "Threads";
        case CATEGORY_DISASSEMBLY: return "Disassembly";
        case CATEGORY_OTHER: return "Other";
        default: return "Unknown";
    }
}

void print_shell_help(void) {
    printf("\nDebugger Commands\n");
    printf("================\n\n");
    
    // Print quick reference first
    printf("Quick Reference:\n");
    printf("---------------\n");
    for (int i = 0; commands[i].name; i++) {
        printf("  %-15s", commands[i].name);
        if (commands[i].alias) {
            printf("(%s)", commands[i].alias);
        } else {
            printf("    ");
        }
        printf(" %s\n", commands[i].description);
    }
    printf("\n");

    // Print detailed command categories
    for (CommandCategory category = 0; category < CATEGORY_COUNT; category++) {
        bool has_commands = false;
        for (int i = 0; commands[i].name; i++) {
            if (commands[i].category == category) {
                has_commands = true;
                break;
            }
        }
        if (!has_commands) continue;

        const char* category_name = category_to_text(category);
        printf("%s Commands:\n", category_name);
        printf("%s\n", str_repeat('-', strlen(category_name) + 10));
        
        for (int i = 0; commands[i].name; i++) {
            if (commands[i].category == category) {
                printf("  %-15s", commands[i].name);
                if (commands[i].alias) {
                    printf("(%s)", commands[i].alias);
                } else {
                    printf("    ");
                }
                printf(" %s\n", commands[i].description);
            }
        }
        printf("\n");
    }
    
    printf("Use 'help <command>' for detailed help on a specific command\n");
}

const DebuggerCommand* find_command(const char* name) {
    if (!name) return NULL;
    
    // Try exact match first
    for (int i = 0; commands[i].name; i++) {
        if (strcasecmp(commands[i].name, name) == 0) {
            return &commands[i];
        }
        if (commands[i].alias && strcasecmp(commands[i].alias, name) == 0) {
            return &commands[i];
        }
    }
    
    // Try partial match
    const DebuggerCommand* partial_match = NULL;
    for (int i = 0; commands[i].name; i++) {
        if (strncasecmp(commands[i].name, name, strlen(name)) == 0) {
            if (!partial_match) {
                partial_match = &commands[i];
            } else {
                // Multiple matches found
                return NULL;
            }
        }
        if (commands[i].alias && strncasecmp(commands[i].alias, name, strlen(name)) == 0) {
            if (!partial_match) {
                partial_match = &commands[i];
            } else {
                // Multiple matches found
                return NULL;
            }
        }
    }
    
    return partial_match;
}

void print_command_help(const char* command_name) {
    const DebuggerCommand* cmd = find_command(command_name);
    if (!cmd) {
        printf("Unknown command: %s\n", command_name);
        return;
    }

    // Print command name and alias
    printf("\nCommand: %s", cmd->name);
    if (cmd->alias) {
        printf(" (alias: %s)", cmd->alias);
    }
    printf("\n");

    // Print description
    if (cmd->description) {
        printf("Description: %s\n", cmd->description);
    }

    // Print syntax
    if (cmd->syntax) {
        printf("Syntax: %s\n", cmd->syntax);
    }

    // Print parameters if available
    if (cmd->has_options && cmd->option_types && cmd->option_descriptions) {
        char* types = strdup(cmd->option_types);
        char* descs = strdup(cmd->option_descriptions);
        char* type_token = strtok(types, "|");
        char* desc_token = strtok(descs, "|");
        
        printf("\nParameters:\n");
        while (type_token && desc_token) {
            printf("  %-15s %s\n", type_token, desc_token);
            type_token = strtok(NULL, "|");
            desc_token = strtok(NULL, "|");
        }
        
        free(types);
        free(descs);
    }

    // Print examples if available
    if (cmd->examples) {
        char* examples = strdup(cmd->examples);
        char* example = strtok(examples, "|");
        char* description = strtok(NULL, "|");
        
        printf("\nExamples:\n");
        while (example && description) {
            printf("  %-30s # %s\n", example, description);
            example = strtok(NULL, "|");
            description = strtok(NULL, "|");
        }
        
        free(examples);
    }

    // Print request/response format if available
    if (cmd->request_format) {
        printf("\nRequest Format:\n%s\n", cmd->request_format);
    }
    if (cmd->response_format) {
        printf("\nResponse Format:\n%s\n", cmd->response_format);
    }

    // Print related events if available
    if (cmd->events) {
        printf("\nRelated Events:\n%s\n", cmd->events);
    }
} 