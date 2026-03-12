#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include <cjson/cJSON.h>
#include "dap_client.h"
#include "dap_protocol.h"
#include "dap_debugger_types.h"
#include "dap_debugger_help.h"


int handle_help_command(DAPClient* client, const char* args) {    
    (void)client; // Unused parameter
    if (!args || !*args) {
        print_shell_help();
        return 0;
    }

    const DebuggerCommand* cmd = find_command(args);
    if (!cmd) {
        printf("Unknown command: %s\n", args);
        return -1;
    }

    print_command_help(args);
    return 0;
}

int handle_quit_command(DAPClient* client, const char* args) {
    (void)args; // Unused parameter
    if (client) {
        DAPDisconnectResult result = {0};
        dap_client_disconnect(client, false, false, &result);
        // Don't free the client here, it will be freed in main.c
    }
    return 1; // Signal to exit
}

int handle_continue_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    int thread_id = client->thread_id;
    bool single_thread = false;
    if (args && *args) {
        thread_id = atoi(args);
        single_thread = true;
    }

    DAPContinueResult result = {0};
    int error = dap_client_continue(client, thread_id, single_thread, &result);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error continuing execution: %d\n", error);
    }
    return 0;
}

int handle_next_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    int thread_id = client->thread_id;
    const char* granularity = "statement";
    bool single_thread = false;
    if (args && *args) {
        thread_id = atoi(args);
        single_thread = true;
    }

    DAPStepResult result = {0};
    int error = dap_client_next(client, thread_id, granularity, single_thread, &result);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error stepping over: %d\n", error);
    }
    return 0;
}

int handle_step_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    int thread_id = client->thread_id;
    if (args && *args) {
        thread_id = atoi(args);
    }

    DAPStepInResult result = {0};
    int error = dap_client_step_in(client, thread_id, NULL, "statement", &result);
    if (error != DAP_ERROR_NONE) {
        printf("Error stepping in: %d\n", error);
    }
    return 0;
}

/// @brief Set source breakpoints
/// @param client DAP client
/// @param args Format: <line> [file] [if <condition>]
/// @return 0 on success
int handle_break_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    if (!args || !*args) {
        printf("Usage: break <line> [file] [if <condition>]\n");
        printf("  break 12          - Set breakpoint at line 12 in current source\n");
        printf("  break 12 hello.c  - Set breakpoint at line 12 in hello.c\n");
        printf("  break 12 if A>0   - Conditional breakpoint\n");
        return 0;
    }

    char* args_copy = strdup(args);
    if (!args_copy) return 0;

    // Parse: <line> [file] [if <condition>]
    int line = 0;
    const char* source_path = client->program_path;
    char* condition = NULL;
    char local_source[256] = {0};

    char* saveptr;
    char* token = strtok_r(args_copy, " ", &saveptr);
    if (!token) {
        free(args_copy);
        printf("Error: line number required\n");
        return 0;
    }

    line = atoi(token);
    if (line <= 0) {
        printf("Error: invalid line number: %s\n", token);
        free(args_copy);
        return 0;
    }

    // Check for optional file or "if"
    token = strtok_r(NULL, " ", &saveptr);
    if (token) {
        if (strcmp(token, "if") == 0) {
            condition = saveptr;
        } else {
            snprintf(local_source, sizeof(local_source), "%s", token);
            source_path = local_source;
            token = strtok_r(NULL, " ", &saveptr);
            if (token && strcmp(token, "if") == 0) {
                condition = saveptr;
            }
        }
    }

    // Build source breakpoint and use the tracking API
    DAPSourceBreakpoint src_bp = {0};
    src_bp.line = line;
    src_bp.condition = (condition && *condition) ? condition : NULL;

    DAPSetBreakpointsResult result = {0};
    int error = dap_client_set_breakpoints(client, source_path, &src_bp, 1, &result);

    if (error != DAP_ERROR_NONE) {
        printf("Error setting breakpoint: %d\n", error);
        if (result.base.message)
            printf("  %s\n", result.base.message);
        dap_set_breakpoints_result_free(&result);
        free(args_copy);
        return 0;
    }

    // Report results
    for (size_t i = 0; i < result.num_breakpoints; i++) {
        if (result.breakpoints[i].verified) {
            printf("Breakpoint %d set at %s:%d",
                   result.breakpoints[i].id, source_path, result.breakpoints[i].line);
            if (condition && *condition)
                printf(" (condition: %s)", condition);
            if (result.breakpoints[i].instruction_reference)
                printf(" @%06o", result.breakpoints[i].instruction_reference);
            printf("\n");
        } else {
            printf("Breakpoint at line %d NOT verified", line);
            if (result.breakpoints[i].message)
                printf(": %s", result.breakpoints[i].message);
            printf("\n");
        }
    }

    dap_set_breakpoints_result_free(&result);
    free(args_copy);
    return 0;
}



/// @brief List source code around the current execution point or a given line
/// @param client DAP client
/// @param args Optional: [line] [file] - line number and/or source file path
/// @return 0 on success
int handle_source_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    const char* source_path = client->program_path;
    int center_line = -1;
    int context_lines = 10; // Show 10 lines before and after

    // Parse args: [line] [file]
    if (args && *args) {
        char* args_copy = strdup(args);
        if (args_copy) {
            char* token = strtok(args_copy, " ");
            if (token) {
                char* endptr;
                long val = strtol(token, &endptr, 10);
                if (*endptr == '\0' && val > 0) {
                    center_line = (int)val;
                    token = strtok(NULL, " ");
                    if (token) source_path = args; // Use original args for path
                } else {
                    // Not a number - treat as filename
                    source_path = args;
                }
            }
            free(args_copy);
        }
    }

    // If no center line specified, try to get current PC line from stack trace
    if (center_line < 0) {
        DAPStackFrame* frames = NULL;
        int frame_count = 0;
        int err = dap_client_get_stack_trace(client, client->thread_id, &frames, &frame_count);
        if (err == DAP_ERROR_NONE && frame_count > 0) {
            center_line = frames[0].line;
            if (frames[0].source_path && *frames[0].source_path) {
                source_path = frames[0].source_path;
            }
        }
        if (frames) {
            for (int i = 0; i < frame_count; i++) {
                free(frames[i].name);
                free(frames[i].source_path);
                free(frames[i].source_name);
                free(frames[i].module_id);
            }
            free(frames);
        }
        if (center_line < 0) center_line = 1;
    }

    if (!source_path || !*source_path) {
        printf("No source file available. Use: list <file>\n");
        return 0;
    }

    FILE* fp = fopen(source_path, "r");
    if (!fp) {
        printf("Cannot open source file: %s\n", source_path);
        return 0;
    }

    int start_line = center_line - context_lines;
    if (start_line < 1) start_line = 1;
    int end_line = center_line + context_lines;

    char line_buf[256];
    int line_num = 0;
    while (fgets(line_buf, sizeof(line_buf), fp)) {
        line_num++;
        if (line_num < start_line) continue;
        if (line_num > end_line) break;

        // Check if this line has a breakpoint
        bool has_bp = false;
        for (int b = 0; b < client->num_breakpoints; b++) {
            if (client->breakpoints[b].verified &&
                client->breakpoints[b].line == line_num) {
                has_bp = true;
                break;
            }
        }

        // Left margin: breakpoint (*) and current line (>>>)
        char bp_mark = has_bp ? '*' : ' ';
        const char* pc_mark = (line_num == center_line) ? ">>>" : "   ";
        printf("%c%s %4d  %s", bp_mark, pc_mark, line_num, line_buf);
        // Add newline if the line doesn't end with one
        size_t len = strlen(line_buf);
        if (len == 0 || line_buf[len - 1] != '\n') {
            printf("\n");
        }
    }

    fclose(fp);
    return 0;
}

int handle_stackTrace_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    int thread_id = client->thread_id;
    if (args && *args) {
        thread_id = atoi(args);
    }

    DAPStackFrame* frames = NULL;
    int frame_count = 0;
    int error = dap_client_get_stack_trace(client, thread_id, &frames, &frame_count);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error getting backtrace: %d (%s)\n", error, dap_error_message(error));
        return 0;
    }

    printf("Stack trace:\n");
    for (int i = 0; i < frame_count; i++) {
        const char* name = frames[i].name ? frames[i].name : "<unknown>";
        const char* src = frames[i].source_name ? frames[i].source_name :
                         (frames[i].source_path ? frames[i].source_path : "");

        if (frames[i].instruction_pointer_reference > 0) {
            printf("  #%d  0%06o in %s", i, frames[i].instruction_pointer_reference, name);
        } else {
            printf("  #%d  %s", i, name);
        }
        if (src[0] && frames[i].line > 0) {
            printf(" at %s:%d", src, frames[i].line);
        }
        printf("\n");
    }

    for (int i = 0; i < frame_count; i++) {
        free(frames[i].name);
        free(frames[i].source_path);
        free(frames[i].source_name);
        free(frames[i].module_id);
    }
    free(frames);
    return 0;
}

int handle_step_out_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    int thread_id = client->thread_id;
    if (args && *args) {
        thread_id = atoi(args);
    }

    DAPStepOutResult result = {0};
    int error = dap_client_step_out(client, thread_id, &result);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error stepping out: %d\n", error);
    }
    return 0;
}

int handle_threads_command(DAPClient* client, const char* args) {
    (void)args;
    if (!client) return 0;

    DAPThread* threads = NULL;
    int thread_count = 0;
    int error = dap_client_get_threads(client, &threads, &thread_count);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error getting threads: %d\n", error);
        return 0;
    }
    
    printf("Threads:\n");
    for (int i = 0; i < thread_count; i++) {
        printf("  %d: %s\n", threads[i].id, threads[i].name);
    }
    
    free(threads);
    return 0;
}

int handle_stack_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    int thread_id = client->thread_id;
    int start_frame = 0;
    int levels = 20;
    
    if (args && *args) {
        char* end;
        thread_id = strtol(args, &end, 10);
        if (*end == ' ') {
            start_frame = strtol(end + 1, &end, 10);
            if (*end == ' ') {
                levels = strtol(end + 1, &end, 10);
            }
        }
    }
    
    DAPStackFrame* frames = NULL;
    int frame_count = 0;
    int error = dap_client_get_stack_trace(client, thread_id, &frames, &frame_count);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error getting stack trace: %d (%s)\n", error, dap_error_message(error));
        return 0;
    }
    
    printf("Stack trace:\n");
    for (int i = start_frame; i < frame_count && i < start_frame + levels; i++) {
        const char* name = frames[i].name ? frames[i].name : "<unknown>";
        const char* src = frames[i].source_name ? frames[i].source_name :
                         (frames[i].source_path ? frames[i].source_path : "");

        if (frames[i].instruction_pointer_reference > 0) {
            printf("  #%d  0%06o in %s", i, frames[i].instruction_pointer_reference, name);
        } else {
            printf("  #%d  %s", i, name);
        }
        if (src[0] && frames[i].line > 0) {
            printf(" at %s:%d", src, frames[i].line);
        }
        printf("\n");
    }

    for (int i = 0; i < frame_count; i++) {
        free(frames[i].name);
        free(frames[i].source_path);
        free(frames[i].source_name);
        free(frames[i].module_id);
    }
    free(frames);
    return 0;
}

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
int print_variables(DAPClient* client, DAPVariable* variables, size_t num_variables, int indent, int max_depth) {
    if (!client || !variables || num_variables == 0 || max_depth < 0) {
        return 1;
    }
    
    char indent_str[32] = {0};
    if (indent > 0) {
        if (indent > sizeof(indent_str) - 1) {
            indent = sizeof(indent_str) - 1;
        }
        memset(indent_str, ' ', indent);
    }
    
    for (size_t i = 0; i < num_variables; i++) {
        DAPVariable* var = &variables[i];
        if (!var->name) {
            continue; // Skip invalid variables
        }
        
        // Print variable name
        printf("%s%s", indent_str, var->name);
        
        // Print type if available
        if (var->type && *var->type) {
            printf(" [%s]", var->type);
        }
        
        // Print value or indication of expandability
        if (var->variables_reference > 0) {
            // This is an expandable variable (struct, array, etc.)
            if (var->value && *var->value) {
                printf(": %s", var->value);
            }
            
            // Print count of children if known
            if (var->named_variables > 0 || var->indexed_variables > 0) {
                printf(" {");
                if (var->named_variables > 0) {
                    printf("%d named", var->named_variables);
                    if (var->indexed_variables > 0) {
                        printf(", ");
                    }
                }
                if (var->indexed_variables > 0) {
                    printf("%d indexed", var->indexed_variables);
                }
                printf("}");
            }
            
            printf("\n");
            
            // Recursively print children if not at max depth
            if (max_depth > 0) {
                DAPGetVariablesResult child_result = {0};
                int error = dap_client_get_variables(client, var->variables_reference, 0, 0, &child_result);
                if (error != DAP_ERROR_NONE) {
                    printf("%s  <Error fetching children: %s>\n", indent_str, dap_error_message(error));
                } else if (child_result.num_variables > 0) {
                    print_variables(client, child_result.variables, child_result.num_variables, indent + 2, max_depth - 1);
                    dap_get_variables_result_free(&child_result);
                } else {
                    printf("%s  <No children>\n", indent_str);
                }
            } else if (max_depth == 0 && var->variables_reference > 0) {
                printf("%s  <Use 'variables %d' to see children>\n", indent_str, var->variables_reference);
            }
        } else {
            // Simple variable with just a value
            if (var->value) {
                printf(" = %s", var->value);
                
                // Show memory reference if available
                if (var->memory_reference>0) {
                    printf(" (Memory: %06o)", var->memory_reference);
                }
            } else {
                printf(" = <undefined>");
            }
            printf("\n");
        }
    }
    
    return 0;
}

int handle_variables_command(DAPClient* client, const char* args) {
    if (!client) {
        fprintf(stderr, "Error: No debugger client available\n");
        return 0; // Don't exit on error
    }
    
    int reference = 0;
    int max_depth = 1; // Default to showing one level of nested variables
    
    // Parse arguments: reference [depth]
    if (args && *args) {
        char* args_copy = strdup(args);
        if (!args_copy) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            return 0;
        }
        
        char* token = strtok(args_copy, " ");
        if (token) {
            reference = atoi(token);
            token = strtok(NULL, " ");
            if (token) {
                max_depth = atoi(token);
                if (max_depth < 0) max_depth = 0;
                if (max_depth > 10) max_depth = 10; // Limit max depth to avoid too much recursion
            }
        }
        free(args_copy);
    }
    
    // If no reference provided, get all scopes and print them
    if (reference <= 0) {
        DAPGetScopesResult scopes_result = {0};
        int error = dap_client_get_scopes(client, 0, &scopes_result);
        if (error != DAP_ERROR_NONE) {
            fprintf(stderr, "Error getting scopes: %d (%s)\n", error, dap_error_message(error));
            return 0;
        }
        
        if (scopes_result.num_scopes == 0) {
            printf("No scopes available in current frame\n");
            dap_get_scopes_result_free(&scopes_result);
            return 0;
        }
        
        printf("Available scopes:\n");
        for (size_t i = 0; i < scopes_result.num_scopes; i++) {
            printf("  %s (ref: %d)\n", 
                scopes_result.scopes[i].name,
                scopes_result.scopes[i].variables_reference);
            
            // Automatically print variables for each scope at depth 1
            DAPGetVariablesResult var_result = {0};
            error = dap_client_get_variables(client, scopes_result.scopes[i].variables_reference, 0, 0, &var_result);
            if (error != DAP_ERROR_NONE) {
                fprintf(stderr, "  Error getting variables for scope %s: %d (%s)\n", 
                    scopes_result.scopes[i].name, error, dap_error_message(error));
                continue;
            }
            
            if (var_result.num_variables > 0) {
                print_variables(client, var_result.variables, var_result.num_variables, 4, max_depth);
            } else {
                printf("    <No variables>\n");
            }
            
            dap_get_variables_result_free(&var_result);
        }
        
        dap_get_scopes_result_free(&scopes_result);
        return 0;
    }
    
    // Get variables for the specified reference
    DAPGetVariablesResult result = {0};
    int error = dap_client_get_variables(client, reference, 0, 0, &result);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error getting variables: %d (%s)\n", error, dap_error_message(error));
        return 0;
    }
    
    if (result.num_variables == 0) {
        printf("No variables available for reference %d\n", reference);
    } else {
        printf("Variables for reference %d:\n", reference);
        print_variables(client, result.variables, result.num_variables, 2, max_depth);
    }
    
    dap_get_variables_result_free(&result);
    return 0;
}

int handle_scopes_command(DAPClient* client, const char* args) {
    if (!client) {
        printf("Error: Debugger not connected\n");
        return -1;
    }

    // First check if we have any threads and if they're stopped
    DAPThread* threads = NULL;
    int thread_count = 0;
    int error = dap_client_get_threads(client, &threads, &thread_count);
    if (error != DAP_ERROR_NONE) {
        printf("Error: Failed to get thread state: %d\n", error);
        return -1;
    }

    // Check if we have any stopped threads
    bool has_stopped_thread = false;
    int stopped_thread_id = 0;
    for (int i = 0; i < thread_count; i++) {
        if (threads[i].state == DAP_THREAD_STATE_STOPPED) {
            has_stopped_thread = true;
            stopped_thread_id = threads[i].id;
            break;
        }
    }

    // Clean up thread memory
    for (int i = 0; i < thread_count; i++) {
        free(threads[i].name);
    }
    free(threads);

    if (!has_stopped_thread) {
        printf("Error: Program must be stopped to view scopes. Use 'pause' or hit a breakpoint first.\n");
        return -1;
    }

    // Get stack trace to find valid frame IDs
    DAPStackFrame* frames = NULL;
    int frame_count = 0;
    error = dap_client_get_stack_trace(client, stopped_thread_id, &frames, &frame_count);
    if (error != DAP_ERROR_NONE || frame_count == 0) {
        printf("Error: No stack frames available\n");
        return -1;
    }

    int frame_id = 0;  // Default to top frame
    if (args && *args) {
        int requested_frame = atoi(args);
        if (requested_frame < frame_count) {
            frame_id = frames[requested_frame].id;
        } else {
            printf("Error: Frame %d not available (only %d frames)\n", requested_frame, frame_count);
            free(frames);
            return -1;
        }
    } else {
        frame_id = frames[0].id;  // Use top frame
    }

    free(frames);

    DAPGetScopesResult result = {0};
    error = dap_client_get_scopes(client, frame_id, &result);
    if (error != DAP_ERROR_NONE) {
        printf("Error getting scopes: %d (%s)\n", error, dap_error_message(error));
        return -1;
    }

    printf("Scopes for frame %d:\n", frame_id);
    for (size_t i = 0; i < result.num_scopes; i++) {
        DAPScope* scope = &result.scopes[i];
        printf("  %s (ref: %d, expensive: %s)\n",
            scope->name,
            scope->variables_reference,
            scope->expensive ? "yes" : "no");
    }

    dap_get_scopes_result_free(&result);
    return 0;
}

int handle_debugmode_command(DAPClient* client, const char* args) {
    if (!client) {
        printf("Error: No active debug session\n");
        return 0;
    }

    // Get current debug mode state
    bool current_mode = client->debug_mode;
    
    // Parse arguments
    if (args && *args) {
        if (strcmp(args, "on") == 0) {
            client->debug_mode = true;            
            printf("Debug mode enabled\n");
        } else if (strcmp(args, "off") == 0) {
            client->debug_mode = false;            
            printf("Debug mode disabled\n");
        } else {
            printf("Invalid argument. Use 'on' or 'off', or no argument to toggle.\n");
            return 0;
        }
    } else {
        // Toggle mode if no arguments
        client->debug_mode = !current_mode;        
        printf("Debug mode %s\n", !current_mode ? "enabled" : "disabled");
    }
    
    return 0;
}

int handle_disassemble_command(DAPClient* client, const char* args) {
    if (!client) {
        fprintf(stderr, "Error: No active debugger connection\n");
        return -1;
    }

    uint32_t memory_reference = 0;
    uint32_t offset = 0;
    size_t instruction_offset = 0;
    size_t instruction_count = 10; // Default to 10 instructions
    bool resolve_symbols = false;
    bool memory_reference_set = false;

    // Parse command line arguments
    if (args && *args) {
        char* args_copy = strdup(args);
        if (args_copy) {
            char* saveptr;
            char* token = strtok_r(args_copy, " ", &saveptr);
            while (token != NULL) {
                if (strcmp(token, "-o") == 0) {
                    token = strtok_r(NULL, " ", &saveptr);
                    if (token) offset = (uint32_t)strtoull(token, NULL, 0);
                } else if (strcmp(token, "-i") == 0) {
                    token = strtok_r(NULL, " ", &saveptr);
                    if (token) instruction_offset = strtoul(token, NULL, 0);
                } else if (strcmp(token, "-c") == 0) {
                    token = strtok_r(NULL, " ", &saveptr);
                    if (token) instruction_count = strtoul(token, NULL, 0);
                } else if (strcmp(token, "-s") == 0) {
                    resolve_symbols = true;
                } else if (!memory_reference_set) {
                    memory_reference = (uint32_t)strtoull(token, NULL, 0);
                    memory_reference_set = true;
                }
                token = strtok_r(NULL, " ", &saveptr);
            }
            free(args_copy);
        }
    }

    if (!memory_reference_set) {
        // Default: disassemble at current PC
        // Use 0 as memory_reference - the server will use the current PC
        memory_reference = 0;
    }

    // Call the disassemble function
    DAPDisassembleResult result = {0};
    int error = dap_client_disassemble(client, memory_reference, offset, 
                                     instruction_offset, instruction_count, 
                                     resolve_symbols, &result);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error: Failed to disassemble memory: %d\n", error);
        return -1;
    }

    // Print the results
    printf("Disassembly of 0x%08x:\n", memory_reference);
    for (size_t i = 0; i < result.num_instructions; i++) {
        printf("0x%s: %s", result.instructions[i].address, 
               result.instructions[i].instruction);
        if (result.instructions[i].symbol) {
            printf(" <%s>", result.instructions[i].symbol);
        }
        printf("\n");
    }

    // Free the result
    dap_disassemble_result_free(&result);
    return 0;
}

/**
 * @brief Set exception breakpoints
 * 
 * @param client The DAP client
 * @param args Command arguments (comma-separated filter names)
 * @return int 0 on success, non-zero on failure
 */
int handle_exception_command(DAPClient* client, const char* args) {
    if (!client) {
        printf("Error: Client not initialized\n");
        return 0;
    }
    
    // Tokenize the arguments by commas
    // If no arguments, then use 'uncaught' as the default filter
    char* args_copy = args ? strdup(args) : strdup("uncaught");
    if (!args_copy) {
        printf("Error: Failed to allocate memory\n");
        return 0;
    }

    // Count the number of filters
    size_t num_filters = 0;
    char* p = args_copy;
    while (*p) {
        if (*p == ',') {
            num_filters++;
        }
        p++;
    }
    num_filters++; // For the last filter
    
    // Allocate memory for the filters
    const char** filters = calloc(num_filters, sizeof(char*));
    if (!filters) {
        printf("Error: Failed to allocate memory for filters\n");
        free(args_copy);
        return 0;
    }
    
    // Parse the filters
    char* token = strtok(args_copy, ",");
    size_t i = 0;
    while (token && i < num_filters) {
        // Trim whitespace
        while (*token && isspace(*token)) {
            token++;
        }
        char* end = token + strlen(token) - 1;
        while (end > token && isspace(*end)) {
            *end-- = '\0';
        }
        
        filters[i++] = token;
        token = strtok(NULL, ",");
    }
    
    // Set exception breakpoints
    DAPSetExceptionBreakpointsResult result = {0};
    int error = dap_client_set_exception_breakpoints(client, filters, i, &result);
    
    // Free memory
    free(filters);
    
    if (error != DAP_ERROR_NONE) {
        printf("Error setting exception breakpoints: %s\n", dap_error_message(error));
        free(args_copy);
        return 0;
    }
    
    // Show result
    printf("Set %zu exception breakpoint filters\n", i);
    for (size_t j = 0; j < i; j++) {
        printf("  - %s\n", filters[j]);
    }
    
    // Free result resources
    if (result.breakpoints) {
        for (size_t j = 0; j < result.num_breakpoints; j++) {
            free(result.breakpoints[j].message);
        }
        free(result.breakpoints);
    }
    
    free(args_copy);
    return 0;
}

/**
 * @brief Handle the info command
 * 
 * @param client The DAP client
 * @param args Command arguments
 * @return int 0 on success, non-zero on failure
 */

int handle_pause_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    int thread_id = client->thread_id;
    if (args && *args) {
        thread_id = atoi(args);
    }

    DAPPauseResult result = {0};
    DAPError error = dap_client_pause(client, thread_id, &result);

    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error pausing execution: %d\n", error);
        return 0;
    }

    printf("Execution paused\n");
    return 0;
}

int handle_evaluate_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    if (!args || !*args) {
        printf("Usage: eval <expression>\n");
        printf("  eval A + B        - Evaluate register expression\n");
        printf("  eval [0x100]      - Read memory at address\n");
        printf("  eval A == 5       - Boolean expression\n");
        return 0;
    }

    // The entire args string is the expression (supports spaces)
    DAPEvaluateResult result = {0};
    DAPError error = dap_client_evaluate(client, args, 0, "repl", &result);

    if (error != DAP_ERROR_NONE) {
        printf("Error evaluating expression: %d\n", error);
        return 0;
    }

    printf("%s", result.result ? result.result : "null");
    if (result.type) {
        printf("  (%s)", result.type);
    }
    printf("\n");

    free(result.result);
    free(result.type);
    return 0;
}

int handle_launch_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    const char* program_file = args;
    if (!program_file || !*program_file) {
        // Use the client's current program if no argument provided
        program_file = client->program_path;
    }

    if (!program_file || !*program_file) {
        printf("Usage: launch <program_file>\n");
        return 0;
    }

    int error = dap_client_launch(client, program_file, true);

    if (error != DAP_ERROR_NONE) {
        printf("Error launching program: %d\n", error);
        return 0;
    }

    printf("Program launched: %s\n", program_file);
    return 0;
}

int handle_read_memory_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    if (!args || !*args) {
        printf("Usage: x <address> [count]\n");
        printf("  address: Octal (0177), hex (0xFF), or decimal address\n");
        printf("  count:   Number of words to read (default: 16)\n");
        printf("Examples:\n");
        printf("  x 0100         - Read 16 words at octal 0100\n");
        printf("  x 0x40 32      - Read 32 words at hex 0x40\n");
        return 0;
    }

    char* args_copy = strdup(args);
    if (!args_copy) return 0;

    char* addr_str = strtok(args_copy, " ");
    char* count_str = strtok(NULL, " ");

    uint32_t address = (uint32_t)strtoul(addr_str, NULL, 0);
    int count = count_str ? atoi(count_str) : 16;
    if (count <= 0) count = 16;
    if (count > 512) count = 512;

    DAPReadMemoryResult result = {0};
    int error = dap_client_read_memory(client, address, 0, count, &result);

    if (error != DAP_ERROR_NONE) {
        printf("Error reading memory at 0%06o: %d\n", address, error);
        free(args_copy);
        return 0;
    }

    // The data comes back as hex string from the server
    if (result.data && *result.data) {
        // Parse hex string data and display as octal words (ND-100 is 16-bit)
        const char* hex = result.data;
        size_t hex_len = strlen(hex);
        int word_count = 0;

        printf("Address  | Octal   Hex    Dec   | ASCII\n");
        printf("---------+----------------------+------\n");

        for (size_t i = 0; i + 3 < hex_len; i += 4) {
            // Each word is 4 hex chars (2 bytes, big-endian)
            char word_hex[5] = { hex[i], hex[i+1], hex[i+2], hex[i+3], '\0' };
            uint16_t word = (uint16_t)strtoul(word_hex, NULL, 16);

            printf(" %06o  | %06o  %04X  %5u  | %c%c\n",
                   address + word_count,
                   word, word, word,
                   ((word >> 8) >= 32 && (word >> 8) <= 126) ? (char)(word >> 8) : '.',
                   ((word & 0xFF) >= 32 && (word & 0xFF) <= 126) ? (char)(word & 0xFF) : '.');
            word_count++;
        }
    } else {
        printf("No data returned\n");
    }

    free(result.address);
    free(result.data);
    free(args_copy);
    return 0;
}

int handle_capabilities_command(DAPClient* client, const char* args) {
    (void)args; // Unused parameter

    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("                    DAP SERVER CAPABILITIES                     \n");
    printf("                   (Debug Adapter Protocol)                    \n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    // Connection Status
    printf("🔗 CONNECTION STATUS\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    if (client) {
        printf("  Server: %s:%d\n", client->host ? client->host : "unknown", client->port);
        printf("  Status: %s\n", client->connected ? "✅ Connected" : "❌ Disconnected");
    } else {
        printf("  Server: Not configured\n");
        printf("  Status: ❌ No connection\n");
    }
    printf("  Transport: TCP\n");
    printf("  Protocol: Debug Adapter Protocol (DAP)\n");
    printf("\n");

    // DAP Initialization Capabilities (as per DAP spec)
    printf("⚙️  DAP INITIALIZATION CAPABILITIES\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  supportsConfigurationDoneRequest: ✅ true\n");
    printf("  supportsFunctionBreakpoints: ❓ unknown\n");
    printf("  supportsConditionalBreakpoints: ❓ unknown\n");
    printf("  supportsHitConditionalBreakpoints: ❓ unknown\n");
    printf("  supportsEvaluateForHovers: ✅ true\n");
    printf("  supportsStepBack: ❓ unknown\n");
    printf("  supportsSetVariable: ❓ unknown\n");
    printf("  supportsRestartFrame: ❓ unknown\n");
    printf("  supportsGotoTargetsRequest: ❌ false\n");
    printf("  supportsStepInTargetsRequest: ❌ false\n");
    printf("  supportsCompletionsRequest: ❌ false\n");
    printf("  supportsModulesRequest: ❓ unknown\n");
    printf("  additionalModuleColumns: ❌ none\n");
    printf("  supportedChecksumAlgorithms: ❌ none\n");
    printf("  supportsRestartRequest: ✅ true\n");
    printf("  supportsExceptionOptions: ❓ unknown\n");
    printf("  supportsValueFormattingOptions: ❌ false\n");
    printf("  supportsExceptionInfoRequest: ❓ unknown\n");
    printf("  supportTerminateDebuggee: ✅ true\n");
    printf("  supportSuspendDebuggee: ✅ true\n");
    printf("  supportsDelayedStackTraceLoading: ❌ false\n");
    printf("  supportsLoadedSourcesRequest: ❌ false\n");
    printf("  supportsLogPoints: ❌ false\n");
    printf("  supportsTerminateThreadsRequest: ❌ false\n");
    printf("  supportsSetExpression: ❌ false\n");
    printf("  supportsTerminateRequest: ✅ true\n");
    printf("  supportsDataBreakpoints: ❌ false\n");
    printf("  supportsReadMemoryRequest: ✅ true\n");
    printf("  supportsWriteMemoryRequest: ❌ false\n");
    printf("  supportsDisassembleRequest: ✅ true\n");
    printf("  supportsCancelRequest: ❌ false\n");
    printf("  supportsBreakpointLocationsRequest: ❌ false\n");
    printf("  supportsClipboardContext: ❌ false\n");
    printf("  supportsSteppingGranularity: ❌ false\n");
    printf("  supportsInstructionBreakpoints: ❌ false\n");
    printf("  supportsExceptionFilterOptions: ❌ false\n");
    printf("  supportsSingleThreadExecutionRequests: ❌ false\n");
    printf("\n");

    // DAP Requests (Commands) Support
    printf("📨 DAP REQUESTS SUPPORT\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  initialize: ✅ Supported\n");
    printf("  configurationDone: ✅ Supported\n");
    printf("  launch: ✅ Supported\n");
    printf("  attach: ✅ Supported\n");
    printf("  restart: ✅ Supported\n");
    printf("  disconnect: ✅ Supported\n");
    printf("  terminate: ✅ Supported\n");
    printf("  setBreakpoints: ✅ Supported\n");
    printf("  setFunctionBreakpoints: ❓ Unknown\n");
    printf("  setExceptionBreakpoints: ✅ Supported\n");
    printf("  dataBreakpointInfo: ❌ Not supported\n");
    printf("  setDataBreakpoints: ❌ Not supported\n");
    printf("  setInstructionBreakpoints: ❌ Not supported\n");
    printf("  continue: ✅ Supported\n");
    printf("  next: ✅ Supported\n");
    printf("  stepIn: ✅ Supported\n");
    printf("  stepOut: ✅ Supported\n");
    printf("  stepBack: ❓ Unknown\n");
    printf("  reverseContinue: ❌ Not supported\n");
    printf("  restartFrame: ❌ Not supported\n");
    printf("  goto: ❌ Not supported\n");
    printf("  pause: ✅ Supported\n");
    printf("  stackTrace: ✅ Supported\n");
    printf("  scopes: ✅ Supported\n");
    printf("  variables: ✅ Supported\n");
    printf("  setVariable: ❓ Unknown\n");
    printf("  source: ✅ Supported\n");
    printf("  threads: ✅ Supported\n");
    printf("  terminateThreads: ❌ Not supported\n");
    printf("  modules: ❓ Unknown\n");
    printf("  loadedSources: ❌ Not supported\n");
    printf("  evaluate: ✅ Supported\n");
    printf("  setExpression: ❌ Not supported\n");
    printf("  stepInTargets: ❌ Not supported\n");
    printf("  gotoTargets: ❌ Not supported\n");
    printf("  completions: ❌ Not supported\n");
    printf("  exceptionInfo: ❓ Unknown\n");
    printf("  readMemory: ✅ Supported\n");
    printf("  writeMemory: ❌ Not supported\n");
    printf("  disassemble: ✅ Supported\n");
    printf("\n");

    // DAP Events Support
    printf("📡 DAP EVENTS SUPPORT\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  initialized: ✅ Supported\n");
    printf("  stopped: ✅ Supported\n");
    printf("  continued: ✅ Supported\n");
    printf("  exited: ✅ Supported\n");
    printf("  terminated: ✅ Supported\n");
    printf("  thread: ✅ Supported\n");
    printf("  output: ✅ Supported\n");
    printf("  breakpoint: ✅ Supported\n");
    printf("  module: ❓ Unknown\n");
    printf("  loadedSource: ❌ Not supported\n");
    printf("  process: ✅ Supported\n");
    printf("  capabilities: ❓ Unknown\n");
    printf("  progressStart: ❌ Not supported\n");
    printf("  progressUpdate: ❌ Not supported\n");
    printf("  progressEnd: ❌ Not supported\n");
    printf("  invalidated: ❌ Not supported\n");
    printf("  memory: ❌ Not supported\n");
    printf("\n");

    // Session Information
    printf("📊 CURRENT SESSION INFORMATION\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    if (client) {
        printf("  Sequence Number: %u\n", client->seq);
        printf("  Timeout: %d ms\n", client->timeout_ms);
        printf("  Debug Mode: %s\n", client->debug_mode ? "✅ Enabled" : "❌ Disabled");
        printf("  Current Thread: %d\n", client->thread_id);
        printf("  Active Breakpoints: %d\n", client->num_breakpoints);
        printf("  Active Watchpoints: %d\n", client->num_data_breakpoints);
        printf("  Loaded Program: %s\n", client->program_path ? client->program_path : "❌ None");
    } else {
        printf("  No active debug session\n");
        printf("  Use 'connect' to establish connection to DAP server\n");
    }
    printf("\n");

    printf("═══════════════════════════════════════════════════════════════\n");
    printf("📚 DAP Specification: https://microsoft.github.io/debug-adapter-protocol/\n");
    printf("💡 Use 'help' to see available commands\n");
    printf("🔧 Use 'debugmode' to toggle protocol debugging\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    return 0;
}

int handle_watch_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    if (!args || !*args) {
        printf("Usage: watch [phys] <address> [read|write|readwrite]\n");
        printf("  watch 01000            - Watch virtual address 01000 for writes\n");
        printf("  watch 01000 read       - Watch virtual address 01000 for reads\n");
        printf("  watch 01000 readwrite  - Watch virtual address 01000 for read/write\n");
        printf("  watch 0x200            - Hex address (virtual)\n");
        printf("  watch phys 01000       - Watch physical address 01000 for writes\n");
        printf("  watch phys 0x200 read  - Watch physical hex address for reads\n");
        return 0;
    }

    char* args_copy = strdup(args);
    if (!args_copy) return 0;

    char* saveptr;
    char* first_token = strtok_r(args_copy, " ", &saveptr);

    // Check for "phys" prefix
    DAPDataBreakpointAddressSpace addr_space = DAP_DATA_BP_ADDR_VIRTUAL;
    char* addr_str = first_token;
    if (first_token && (strcmp(first_token, "phys") == 0 || strcmp(first_token, "physical") == 0)) {
        addr_space = DAP_DATA_BP_ADDR_PHYSICAL;
        addr_str = strtok_r(NULL, " ", &saveptr);
    }

    char* access_str = strtok_r(NULL, " ", &saveptr);

    if (!addr_str) {
        printf("Error: address required\n");
        free(args_copy);
        return 0;
    }

    // Parse address (octal by default for ND-100)
    uint32_t address = (uint32_t)strtoul(addr_str, NULL, 0);

    // Parse access type (default: write)
    DAPDataBreakpointAccessType access = DAP_DATA_BP_ACCESS_WRITE;
    if (access_str) {
        if (strcmp(access_str, "read") == 0)
            access = DAP_DATA_BP_ACCESS_READ;
        else if (strcmp(access_str, "readwrite") == 0 || strcmp(access_str, "rw") == 0)
            access = DAP_DATA_BP_ACCESS_READWRITE;
    }

    // Format data_id with address space prefix (V: or P:) and octal address
    char data_id[32];
    snprintf(data_id, sizeof(data_id), "%c:%06o",
             addr_space == DAP_DATA_BP_ADDR_PHYSICAL ? 'P' : 'V', address);

    // Build the request including all existing data breakpoints plus this new one
    int existing_count = 0;
    const DAPDataBreakpoint* existing = dap_client_get_data_breakpoints(client, &existing_count);

    int total = existing_count + 1;
    DAPDataBreakpoint* all_bps = calloc(total, sizeof(DAPDataBreakpoint));
    if (!all_bps) {
        free(args_copy);
        return 0;
    }

    // Copy existing
    for (int i = 0; i < existing_count; i++) {
        if (existing[i].data_id)
            all_bps[i].data_id = strdup(existing[i].data_id);
        all_bps[i].access_type = existing[i].access_type;
        all_bps[i].address_space = existing[i].address_space;
        all_bps[i].address = existing[i].address;
    }

    // Add new one
    all_bps[existing_count].data_id = strdup(data_id);
    all_bps[existing_count].access_type = access;
    all_bps[existing_count].address_space = addr_space;
    all_bps[existing_count].address = address;

    DAPSetDataBreakpointsResult result = {0};
    int error = dap_client_set_data_breakpoints(client, all_bps, total, &result);

    // Free temporary array
    for (int i = 0; i < total; i++)
        free(all_bps[i].data_id);
    free(all_bps);

    if (error != DAP_ERROR_NONE) {
        printf("Error setting watchpoint: %d\n", error);
        if (result.base.message)
            printf("  %s\n", result.base.message);
        dap_set_data_breakpoints_result_free(&result);
        free(args_copy);
        return 0;
    }

    // Report the last added watchpoint
    if (result.num_breakpoints > 0) {
        size_t last = result.num_breakpoints - 1;
        const char* type_str = "write";
        switch (access) {
            case DAP_DATA_BP_ACCESS_READ:      type_str = "read"; break;
            case DAP_DATA_BP_ACCESS_WRITE:     type_str = "write"; break;
            case DAP_DATA_BP_ACCESS_READWRITE: type_str = "read/write"; break;
        }
        const char* space_str = addr_space == DAP_DATA_BP_ADDR_PHYSICAL ? "phys" : "virt";
        if (result.breakpoints[last].verified) {
            printf("Watchpoint %d set at %s %06o (%s)\n",
                   result.breakpoints[last].id, space_str, address, type_str);
        } else {
            printf("Watchpoint at %s %06o NOT verified", space_str, address);
            if (result.breakpoints[last].message)
                printf(": %s", result.breakpoints[last].message);
            printf("\n");
        }
    }

    dap_set_data_breakpoints_result_free(&result);
    free(args_copy);
    return 0;
}

int handle_info_command(DAPClient* client, const char* args) {
    if (!client) return 0;

    if (!args || !*args) {
        printf("Usage: info breakpoints|watchpoints\n");
        printf("  info breakpoints   - List all source breakpoints\n");
        printf("  info watchpoints   - List all data breakpoints (watchpoints)\n");
        printf("  info b             - Short for breakpoints\n");
        printf("  info w             - Short for watchpoints\n");
        return 0;
    }

    if (strncmp(args, "breakpoints", 11) == 0 || strcmp(args, "b") == 0 ||
        strncmp(args, "break", 5) == 0) {
        int count = 0;
        const DAPBreakpoint* bps = dap_client_get_breakpoints(client, &count);

        if (count == 0) {
            printf("No breakpoints set.\n");
            return 0;
        }

        printf("Num  Verified  Line  Address   Condition  Source\n");
        printf("---  --------  ----  --------  ---------  ------\n");
        for (int i = 0; i < count; i++) {
            printf("%-3d  %-8s  %-4d  ",
                   bps[i].id ? bps[i].id : i + 1,
                   bps[i].verified ? "yes" : "no",
                   bps[i].line);
            if (bps[i].instruction_reference)
                printf("%06o    ", bps[i].instruction_reference);
            else
                printf("          ");
            if (bps[i].condition)
                printf("%-9s  ", bps[i].condition);
            else
                printf("           ");
            if (bps[i].source_path)
                printf("%s", bps[i].source_path);
            printf("\n");
        }
        return 0;
    }

    if (strncmp(args, "watchpoints", 11) == 0 || strcmp(args, "w") == 0 ||
        strncmp(args, "watch", 5) == 0) {
        int count = 0;
        const DAPDataBreakpoint* wps = dap_client_get_data_breakpoints(client, &count);

        if (count == 0) {
            printf("No watchpoints set.\n");
            return 0;
        }

        printf("Num  Verified  Space  Address   Access     Condition\n");
        printf("---  --------  -----  --------  ---------  ---------\n");
        for (int i = 0; i < count; i++) {
            const char* type_str = "write";
            switch (wps[i].access_type) {
                case DAP_DATA_BP_ACCESS_READ:      type_str = "read"; break;
                case DAP_DATA_BP_ACCESS_WRITE:     type_str = "write"; break;
                case DAP_DATA_BP_ACCESS_READWRITE: type_str = "readwrite"; break;
            }
            const char* space_str = wps[i].address_space == DAP_DATA_BP_ADDR_PHYSICAL ? "phys" : "virt";
            printf("%-3d  %-8s  %-5s  %06o    %-9s  ",
                   wps[i].id ? wps[i].id : i + 1,
                   wps[i].verified ? "yes" : "no",
                   space_str,
                   wps[i].address,
                   type_str);
            if (wps[i].condition)
                printf("%s", wps[i].condition);
            printf("\n");
        }
        return 0;
    }

    printf("Unknown info topic: %s\n", args);
    printf("Use: info breakpoints, info watchpoints\n");
    return 0;
}
