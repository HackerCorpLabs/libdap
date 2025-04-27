#include "dap_debugger_ui.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include "dap_debugger_help.h"

void print_usage(const char* program_name) {
    printf("Usage: %s [options] [program_file]\n", program_name);
    printf("Options:\n");
    printf("  -h, --host HOST     Specify the host to connect to (default: localhost)\n");
    printf("  -p, --port PORT     Specify the port to connect to (default: 4711)\n");
    printf("  -f, --file FILE     Program file to debug (alternative to positional argument)\n");
    printf("  -b, --break LINE    Set breakpoint at line (can be specified multiple times)\n");
    printf("  -?, --help          Display this help message and exit\n");
    printf("\n");
    printf("Program file:\n");
    printf("  The program file can be an assembly source file (.asm), binary file (.bin),\n");
    printf("  or any other file format supported by the debugger. The server will\n");
    printf("  automatically look for related files (binary, map) in the same directory.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -f program.asm -h localhost -p 4711\n", program_name);
    printf("  %s program.asm -h localhost -p 4711\n", program_name);
    printf("  %s program.asm -b 10 -b 20\n", program_name);
}

void print_command_with_cursor(const char* cmd, int cursor_pos) {
    (void)cursor_pos;  // Mark parameter as intentionally unused
    printf("\r(dap) %s", cmd);
    fflush(stdout);
}

static int get_command_matches(const char* prefix, const char** matches, int max_matches) {
    int count = 0;
    for (int i = 0; commands[i].name && count < max_matches; i++) {
        if (strncmp(prefix, commands[i].name, strlen(prefix)) == 0) {
            matches[count++] = commands[i].name;
        }
        if (commands[i].alias && strncmp(prefix, commands[i].alias, strlen(prefix)) == 0) {
            matches[count++] = commands[i].alias;
        }
    }
    return count;
}

void handle_tab_completion(char* cmd, int* cursor_pos) {
    char* prefix = cmd;
    size_t prefix_len = *cursor_pos;
    while (prefix_len > 0 && !isspace(prefix[prefix_len - 1])) {
        prefix_len--;
    }
    prefix += prefix_len;
    const char* matches[32];
    int match_count = get_command_matches(prefix, matches, 32);
    if (match_count == 0) {
        return;
    }
    if (match_count == 1) {
        strcpy(prefix, matches[0]);
        *cursor_pos = prefix_len + strlen(matches[0]);
        printf("\r(dap) %s", cmd);
        fflush(stdout);
        return;
    }
    size_t common_prefix_len = strlen(prefix);
    bool found_common = true;
    while (found_common) {
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
    if (common_prefix_len > strlen(prefix)) {
        strncpy(prefix, matches[0], common_prefix_len);
        prefix[common_prefix_len] = '\0';
        *cursor_pos = prefix_len + common_prefix_len;
        printf("\r(dap) %s", cmd);
        fflush(stdout);
    }
    printf("\n");
    for (int i = 0; i < match_count; i++) {
        printf("%s ", matches[i]);
    }
    printf("\n(dap) %s", cmd);
    fflush(stdout);
} 