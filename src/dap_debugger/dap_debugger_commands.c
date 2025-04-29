#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "../libdap/include/dap_client.h"
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
        dap_client_free(client);
    }
    return 1; // Signal to exit
}

int handle_continue_command(DAPClient* client, const char* args) {
    if (!client) return 1;
    
    int thread_id = 0;
    bool single_thread = false;
    if (args && *args) {
        thread_id = atoi(args);
        single_thread = true;
    }
    
    DAPContinueResult result = {0};
    int error = dap_client_continue(client, thread_id, single_thread, &result);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error continuing execution: %d\n", error);
        return 1;
    }
    return 0;
}

int handle_next_command(DAPClient* client, const char* args) {
    if (!client) return 1;
    
    int thread_id = 0;
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
        return 1;
    }
    return 0;
}

int handle_step_command(DAPClient* client, const char* args) {
    if (!client) {
        printf("Error: Debugger not connected\n");
        return -1;
    }

    // Get current thread state
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
        printf("Error: No threads are stopped\n");
        return -1;
    }

    // Parse thread ID from args if provided
    int thread_id = stopped_thread_id;
    if (args && *args) {
        char* endptr;
        int parsed_id = strtol(args, &endptr, 10);
        if (endptr != args && *endptr == '\0') {
            thread_id = parsed_id;
        }
    }

    // Create step-in request
    cJSON* request_args = cJSON_CreateObject();
    if (!request_args) {
        printf("Error: Failed to create step-in request\n");
        return -1;
    }

    cJSON_AddNumberToObject(request_args, "threadId", thread_id);
    cJSON_AddStringToObject(request_args, "granularity", "statement");
    cJSON_AddBoolToObject(request_args, "singleThread", true);

    // Send step-in request
    char* response_body = NULL;
    error = dap_client_send_request(client, DAP_CMD_STEP_IN, request_args, &response_body);
    cJSON_Delete(request_args);

    if (error != DAP_ERROR_NONE) {
        printf("Error: Failed to send step-in request: %d\n", error);
        return -1;
    }

    if (!response_body) {
        printf("Error: Invalid step-in response\n");
        return -1;
    }

    // Parse response body
    cJSON* body = cJSON_Parse(response_body);
    free(response_body);
    
    if (!body) {
        printf("Error: Failed to parse step-in response\n");
        return -1;
    }

    // Check if all threads are stopped
    cJSON* all_threads_stopped = cJSON_GetObjectItem(body, "allThreadsStopped");
    if (all_threads_stopped && cJSON_IsBool(all_threads_stopped)) {
        if (cJSON_IsTrue(all_threads_stopped)) {
            printf("All threads stopped\n");
        } else {
            printf("Only current thread stopped\n");
        }
    }

    cJSON_Delete(body);

    // Wait for stopped event
    printf("Stepping...\n");
    fflush(stdout);

    return 0;
}

int handle_break_command(DAPClient* client, const char* args) {
    if (!client) return 1;
    
    if (!args || !*args) {
        // List breakpoints - keep existing functionality
        DAPBreakpoint* breakpoints = client->breakpoints;
        int count = client->num_breakpoints;
        
        printf("Breakpoints:\n");
        for (int i = 0; i < count; i++) {
            printf("  %d: %s:%d\n", breakpoints[i].id, 
                   breakpoints[i].source ? breakpoints[i].source->path : "unknown",
                   breakpoints[i].line);
        }
        return 0;
    }
    
    // Parse line number and optional file path
    char* args_copy = strdup(args);
    if (!args_copy) {
        fprintf(stderr, "Error: Out of memory\n");
        return 1;
    }
    
    int line = 0;
    char* file_path = NULL;
    
    // Check if the format is "file:line" or just "line"
    char* colon = strchr(args_copy, ':');
    if (colon) {
        // Format is "file:line"
        *colon = '\0'; // Split at colon
        file_path = args_copy;
        
        char* line_str = colon + 1;
        char* endptr;
        line = strtol(line_str, &endptr, 10);
        if (endptr == line_str || *endptr != '\0') {
            fprintf(stderr, "Error: Invalid line number '%s'\n", line_str);
            free(args_copy);
            return 1;
        }
    } else {
        // Just a line number, or possibly "line file"
        char* endptr;
        line = strtol(args_copy, &endptr, 10);
        if (endptr == args_copy) {
            fprintf(stderr, "Error: Invalid line number\n");
            free(args_copy);
            return 1;
        }
        
        // Check if there's a file path after the line number
        while (*endptr == ' ' || *endptr == '\t') endptr++;
        if (*endptr != '\0') {
            file_path = endptr;
        }
    }
    
    // If no file path specified, try to use the current source
    if (!file_path || !*file_path) {
        if (client->program_path) {
            file_path = client->program_path;
        } else {
            fprintf(stderr, "Error: No source file specified and no current file available\n");
            free(args_copy);
            return 1;
        }
    }
    
    // Create the breakpoint
    DAPSourceBreakpoint bp = {0};
    bp.line = line;
    bp.column = 0;  // Column is optional, use 0 to ignore
    bp.condition = NULL;  // No condition by default
    
    DAPSetBreakpointsResult result = {0};
    int error = dap_client_set_breakpoints(client, file_path, &bp, 1, &result);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error setting breakpoint: %s\n", dap_error_message(error));
        free(args_copy);
        return 1;
    }
    
    if (result.num_breakpoints > 0 && result.breakpoints[0].verified) {
        printf("Breakpoint set at %s:%d\n", file_path, line);
    } else {
        if (result.num_breakpoints > 0 && result.breakpoints[0].message) {
            printf("Warning: Breakpoint may not be valid: %s\n", result.breakpoints[0].message);
        } else {
            printf("Warning: Breakpoint may not be valid\n");
        }
    }
    
    // Free memory and the result
    free(args_copy);
    for (size_t i = 0; i < result.num_breakpoints; i++) {
        free(result.breakpoints[i].message);
        // Other fields like condition, hit_condition, and log_message would also need to be freed if they were allocated
    }
    free(result.breakpoints);
    
    return 0;
}

int handle_delete_command(DAPClient* client, const char* args) {
    if (!client || !args || !*args) {
        fprintf(stderr, "Usage: delete <breakpoint_id>\n");
        return 1;
    }
    
    int id = atoi(args);
    DAPBreakpoint* bp = dap_client_get_breakpoint_by_id(client, id);
    if (!bp) {
        fprintf(stderr, "Breakpoint %d not found\n", id);
        return 1;
    }
    
    // Clear breakpoint by setting an empty array
    DAPSetBreakpointsResult result = {0};
    int error = dap_client_set_breakpoints(client, bp->source->path, NULL, 0, &result);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error deleting breakpoint: %d\n", error);
        return 1;
    }
    return 0;
}

int handle_list_command(DAPClient* client, const char* args) {
    if (!client) return 1;
    
    const char* source_path = NULL;
    int source_reference = 0;
    
    if (args && *args) {
        char* comma = strchr(args, ',');
        if (comma) {
            *comma = '\0';
            source_path = args;
            source_reference = atoi(comma + 1);
        } else {
            source_path = args;
        }
    }
    
    DAPSourceResult result = {0};
    int error = dap_client_source(client, source_path, source_reference, &result);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error getting source: %d\n", error);
        return 1;
    }
    
    if (result.content) {
        printf("%s\n", result.content);
        free(result.content);
    }
    return 0;
}

int handle_backtrace_command(DAPClient* client, const char* args) {
    if (!client) return 1;
    
    int thread_id = 0;
    if (args && *args) {
        thread_id = atoi(args);
    }
    
    DAPStackFrame* frames = NULL;
    int frame_count = 0;
    int error = dap_client_get_stack_trace(client, thread_id, &frames, &frame_count);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error getting backtrace: %d\n", error);
        return 1;
    }
    
    printf("Stack trace:\n");
    for (int i = 0; i < frame_count; i++) {
        printf("  #%d %s:%d\n", i, 
               frames[i].source ? frames[i].source->path : "unknown",
               frames[i].line);
    }
    
    free(frames);
    return 0;
}

int handle_step_out_command(DAPClient* client, const char* args) {
    if (!client) return 1;
    
    int thread_id = 0;
    if (args && *args) {
        thread_id = atoi(args);
    }
    
    DAPStepOutResult result = {0};
    int error = dap_client_step_out(client, thread_id, &result);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error stepping out: %d\n", error);
        return 1;
    }
    return 0;
}

int handle_threads_command(DAPClient* client, const char* args) {
    (void)args; // Unused parameter
    if (!client) return 1;
    
    DAPThread* threads = NULL;
    int thread_count = 0;
    int error = dap_client_get_threads(client, &threads, &thread_count);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error getting threads: %d\n", error);
        return 1;
    }
    
    printf("Threads:\n");
    for (int i = 0; i < thread_count; i++) {
        printf("  %d: %s\n", threads[i].id, threads[i].name);
    }
    
    free(threads);
    return 0;
}

int handle_stack_command(DAPClient* client, const char* args) {
    if (!client) return 1;
    
    int thread_id = 0;
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
        fprintf(stderr, "Error getting stack trace: %d\n", error);
        return 1;
    }
    
    printf("Stack trace:\n");
    for (int i = start_frame; i < frame_count && i < start_frame + levels; i++) {
        printf("  #%d %s:%d\n", i, 
               frames[i].source ? frames[i].source->path : "unknown",
               frames[i].line);
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
                if (var->memory_reference && *var->memory_reference) {
                    printf(" (Memory: %s)", var->memory_reference);
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
    if (!client) return 1;
    
    int frame_id = 0;
    if (args && *args) {
        frame_id = atoi(args);
    }
    
    DAPGetScopesResult result = {0};
    int error = dap_client_get_scopes(client, frame_id, &result);
    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error getting scopes: %d\n", error);
        return 1;
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
        return 1;
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
            return 1;
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

    char* memory_reference = NULL;
    uint64_t offset = 0;
    size_t instruction_offset = 0;
    size_t instruction_count = 10; // Default to 10 instructions
    bool resolve_symbols = false;

    // Parse command line arguments
    char* saveptr;
    char* token = strtok_r((char*)args, " ", &saveptr);
    while (token != NULL) {
        if (strcmp(token, "-o") == 0) {
            token = strtok_r(NULL, " ", &saveptr);
            if (token) offset = strtoull(token, NULL, 0);
        } else if (strcmp(token, "-i") == 0) {
            token = strtok_r(NULL, " ", &saveptr);
            if (token) instruction_offset = strtoul(token, NULL, 0);
        } else if (strcmp(token, "-c") == 0) {
            token = strtok_r(NULL, " ", &saveptr);
            if (token) instruction_count = strtoul(token, NULL, 0);
        } else if (strcmp(token, "-s") == 0) {
            resolve_symbols = true;
        } else {
            memory_reference = token;
        }
        token = strtok_r(NULL, " ", &saveptr);
    }

    if (!memory_reference) {
        fprintf(stderr, "Error: Memory reference is required\n");
        return -1;
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
    printf("Disassembly of %s:\n", memory_reference);
    for (size_t i = 0; i < result.num_instructions; i++) {
        printf("0x%016llx: %s", (unsigned long long)result.instructions[i].address, 
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