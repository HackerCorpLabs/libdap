#include "dap_debugger_ui.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include "dap_debugger_help.h"

void print_usage(const char* program_name) {
    printf("Usage: %s [options] [program_file]\n", program_name);
    printf("Options:\n");
    printf("  -h, --host HOST           Specify the host to connect to (default: localhost)\n");
    printf("  -p, --port PORT           Specify the port to connect to (default: 4711)\n");
    printf("  -e, --stop-on-entry       Stop at program entry point\n");
    printf("  -f, --program FILE        Program file to debug (alternative to positional argument)\n");
    printf("  -a, --args ARGS           Comma-separated list of arguments for the program\n");
    printf("  -v, --env VARS            Comma-separated list of environment variables (NAME=VALUE,...)\n");
    printf("  -d, --cwd DIR             Working directory for the program\n");
    printf("  -b, --break LINE          Set breakpoint at line (can be specified multiple times)\n");
    printf("  -?, --help                Display this help message and exit\n");
    printf("\n");
    printf("Program file:\n");
    printf("  The program file can be an assembly source file (.asm), binary file (.bin),\n");
    printf("  or any other file format supported by the debugger. The server will\n");
    printf("  automatically look for related files (binary, map) in the same directory.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -f program.asm -h localhost -p 4711\n", program_name);
    printf("  %s program.asm -e\n", program_name);
    printf("  %s --program=program.asm --args=arg1,arg2,arg3\n", program_name);
    printf("  %s --program=program.asm --env=VAR1=value1,VAR2=value2 --cwd=/tmp\n", program_name);
    printf("  %s program.asm -b 10 -b 20\n", program_name);
}


#define CONSOLE_PROMPT "(dap)" 

void print_command_with_cursor(const char* cmd, int cursor_pos) {
    (void)cursor_pos;  // Mark parameter as intentionally unused
    printf("\r%s %s", CONSOLE_PROMPT, cmd);
    fflush(stdout);
}


/**
 * Get command completions that match a given prefix
 * 
 * @param prefix The prefix to match against commands
 * @param matches Array to store matched commands
 * @param max_matches Maximum number of matches to return
 * @return Number of matches found
 */
static int get_command_matches(const char* prefix, const char** matches, int max_matches) {
    int match_count = 0;
    
    for (int i = 0; commands[i].name != NULL; i++) {
        // Check primary command name (case-insensitive)
        if (strncasecmp(prefix, commands[i].name, strlen(prefix)) == 0) {
            if (match_count < max_matches) {
                matches[match_count++] = commands[i].name;
            }
        }
        // Check alias if it exists and is different from the name (case-insensitive)
        else if (commands[i].alias && 
                 strncasecmp(prefix, commands[i].alias, strlen(prefix)) == 0 &&
                 strcasecmp(commands[i].name, commands[i].alias) != 0) {
            if (match_count < max_matches) {
                matches[match_count++] = commands[i].name;
            }
        }
    }
    
    return match_count;
}

/**
 * @brief Get parameter completions for a specific command
 * 
 * @param command Command name
 * @param prefix Prefix of parameter to match
 * @param matches Array to store matching parameters
 * @param max_matches Maximum number of matches to return
 * @return int Number of matches found
 */
static int get_parameter_matches(const char* command, const char* prefix, const char** matches, int max_matches) {
    int match_count = 0;
    
    // Find the command in the command table
    const DebuggerCommand* cmd = find_command(command);
    if (!cmd) {
        return 0;
                }
    
    // If command has options, parse them from option_types
    if (cmd->has_options && cmd->option_types) {
        char* options = strdup(cmd->option_types);
        if (!options) {
            return 0;
                }
        
        char* option = strtok(options, "|");
        while (option && match_count < max_matches) {
            if (strncmp(prefix, option, strlen(prefix)) == 0) {
                matches[match_count++] = option;
                }
            option = strtok(NULL, "|");
        }
        
        free(options);
    }
    
    // If we have examples, parse them for additional suggestions
    if (cmd->examples && match_count < max_matches) {
        char* examples = strdup(cmd->examples);
        if (!examples) {
            return match_count;
        }
        
        char* example = strtok(examples, "|");
        while (example && match_count < max_matches) {
            // Skip the description part of the example
            char* desc = strchr(example, '|');
            if (desc) {
                *desc = '\0';
                }
            
            // Check if this example matches the prefix
            if (strncmp(prefix, example, strlen(prefix)) == 0) {
                matches[match_count++] = example;
            }
            
            example = strtok(NULL, "|");
                }
        
        free(examples);
    }
    
    return match_count;
}

void handle_tab_completion(char* cmd, int* cursor_pos) {
    // Make a copy of the command for tokenizing
    char* cmd_copy = strdup(cmd);
    if (!cmd_copy) return;
    
    // Identify the word we're completing
    char* prefix = cmd + *cursor_pos;
    while (prefix > cmd && !isspace(*(prefix - 1))) {
        prefix--;
    }
    size_t prefix_len = *cursor_pos - (prefix - cmd);
    
    // Extract the current word we're trying to complete
    char current_word[256] = {0};
    strncpy(current_word, prefix, prefix_len);
    current_word[prefix_len] = '\0';
    
    // Check if we're completing a command or a parameter
    char* saveptr = NULL;
    char* command = strtok_r(cmd_copy, " ", &saveptr);
    
    const char* matches[32];
    int match_count = 0;
    
    if (prefix == cmd) {
        // We're at the start of the line, completing a command
        match_count = get_command_matches(current_word, matches, 32);
    } else {
        // We're completing a parameter for a command
        match_count = get_parameter_matches(command, current_word, matches, 32);
        
        // If we didn't find any parameter matches, fall back to command completion
        if (match_count == 0) {
            match_count = get_command_matches(current_word, matches, 32);
        }
    }
    
    if (match_count == 0) {
        free(cmd_copy);
        return;
    }
    
    if (match_count == 1) {
        // Replace the current word with the completion
        memmove(cmd + (prefix - cmd) + strlen(matches[0]), 
                cmd + (prefix - cmd) + prefix_len, 
                strlen(cmd) - (prefix - cmd) - prefix_len + 1);
        memcpy(prefix, matches[0], strlen(matches[0]));
        
        // Update cursor position
        *cursor_pos = (prefix - cmd) + strlen(matches[0]);
        
        // If we completed a command, add a space
        if (prefix == cmd) {
            cmd[*cursor_pos] = ' ';
            cmd[*cursor_pos + 1] = '\0';
            (*cursor_pos)++;
        }
        
        // Display the updated command
        printf("\r%s %s", CONSOLE_PROMPT, cmd);
        fflush(stdout);
        free(cmd_copy);
        return;
    }
    
    // Find common prefix among matches
    size_t common_prefix_len = 0;
    bool found_common = true;
    
    while (found_common) {
        if (common_prefix_len >= strlen(matches[0])) {
            break;
        }
        
        char current_char = matches[0][common_prefix_len];
        if (current_char == '\0') {
            break;
        }
        
        for (int i = 1; i < match_count; i++) {
            if (matches[i][common_prefix_len] != current_char) {
                found_common = false;
                break;
            }
        }
        
        if (found_common) {
            common_prefix_len++;
        }
    }
    
    if (common_prefix_len > prefix_len) {
        // Replace the current word with the common prefix
        char common_prefix[256];
        strncpy(common_prefix, matches[0], common_prefix_len);
        common_prefix[common_prefix_len] = '\0';
        
        memmove(cmd + (prefix - cmd) + common_prefix_len, 
                cmd + (prefix - cmd) + prefix_len, 
                strlen(cmd) - (prefix - cmd) - prefix_len + 1);
        memcpy(prefix, common_prefix, common_prefix_len);
        
        // Update cursor position
        *cursor_pos = (prefix - cmd) + common_prefix_len;
        
        printf("\r%s %s", CONSOLE_PROMPT, cmd);
        fflush(stdout);
    }
    
    // Show all completions
    printf("\nCompletions:\n");
    for (int i = 0; i < match_count; i++) {
        printf("  %s\n", matches[i]);
    }
    printf("%s %s", CONSOLE_PROMPT, cmd);
    fflush(stdout);
    
    free(cmd_copy);
} 