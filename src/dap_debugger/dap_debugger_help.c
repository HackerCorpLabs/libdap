
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
        if (!commands[i].implemented) continue;
        printf("  %-15s", commands[i].name);
        if (commands[i].alias || commands[i].alias2) {
            printf("(");
            if (commands[i].alias2) printf("%s", commands[i].alias2);
            if (commands[i].alias && commands[i].alias2) printf(",");
            if (commands[i].alias) printf("%s", commands[i].alias);
            printf(")");
        } else {
            printf("     ");
        }
        printf(" %s\n", commands[i].description);
    }
    printf("\n");

    // Print detailed command categories
    for (CommandCategory category = 0; category < CATEGORY_COUNT; category++) {
        bool has_commands = false;
        for (int i = 0; commands[i].name; i++) {
            if (commands[i].category == category && commands[i].implemented) {
                has_commands = true;
                break;
            }
        }
        if (!has_commands) continue;

        const char* category_name = category_to_text(category);
        printf("%s Commands:\n", category_name);
        printf("%s\n", str_repeat('-', strlen(category_name) + 10));
        
        for (int i = 0; commands[i].name; i++) {
            if (commands[i].category == category && commands[i].implemented) {
                printf("  %-15s", commands[i].name);
                if (commands[i].alias || commands[i].alias2) {
                    printf("(");
                    if (commands[i].alias2) printf("%s", commands[i].alias2);
                    if (commands[i].alias && commands[i].alias2) printf(",");
                    if (commands[i].alias) printf("%s", commands[i].alias);
                    printf(")");
                } else {
                    printf("     ");
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
        if (commands[i].alias2 && strcasecmp(commands[i].alias2, name) == 0) {
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
        if (commands[i].alias2 && strncasecmp(commands[i].alias2, name, strlen(name)) == 0) {
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

    // Print command name and aliases
    printf("\nCommand: %s", cmd->name);
    if (cmd->alias || cmd->alias2) {
        printf(" (aliases: ");
        if (cmd->alias2) printf("%s", cmd->alias2);
        if (cmd->alias && cmd->alias2) printf(", ");
        if (cmd->alias) printf("%s", cmd->alias);
        printf(")");
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

    // Print implementation status
    printf("\nImplemented: %s\n", cmd->implemented ? "Yes" : "No");
}

void print_unsupported_commands(void) {
    printf("\nUnsupported DAP Commands:\n");
    printf("========================\n\n");

    bool found_unsupported = false;
    for (CommandCategory category = 0; category < CATEGORY_COUNT; category++) {
        bool has_unsupported = false;
        for (int i = 0; commands[i].name; i++) {
            if (commands[i].category == category && !commands[i].implemented) {
                has_unsupported = true;
                break;
            }
        }
        if (!has_unsupported) continue;

        const char* category_name = category_to_text(category);
        printf("%s Commands:\n", category_name);
        printf("%s\n", str_repeat('-', strlen(category_name) + 10));

        for (int i = 0; commands[i].name; i++) {
            if (commands[i].category == category && !commands[i].implemented) {
                printf("  %-15s %s\n", commands[i].name, commands[i].description);
                found_unsupported = true;
            }
        }
        printf("\n");
    }

    if (!found_unsupported) {
        printf("All defined DAP commands are implemented!\n");
    }

    printf("Note: These commands are defined in the DAP specification but not yet implemented in this debugger.\n");
}