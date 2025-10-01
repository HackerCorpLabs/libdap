#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include "dap_client.h"
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

    // Send step-in request using the proper API
    DAPStepInResult result = {0};
    error = dap_client_step_in(client, thread_id, NULL, "statement", &result);

    if (error != DAP_ERROR_NONE) {
        printf("Error: Failed to send step-in request: %d\n", error);
        return -1;
    }

    printf("Stepping into...\n");

    return 0;
}

/// @brief Delete 
/// @param client 
/// @param args 
/// @return 
int handle_break_command(DAPClient* client, const char* args) {
    if (!client) return 1;
   
    // TODO: Need to implement BREAK command (which is NOT set breakpoints)
    
    return 0;
}



/// @brief List source code
/// @param client 
/// @param args 
/// @return 
int handle_source_command(DAPClient* client, const char* args) {
    if (!client) return 1;
  
     // TODO: Implement list command

    return 0;
}

int handle_stackTrace_command(DAPClient* client, const char* args) {
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
               client->program_path,
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
               frames[i].source_name ? frames[i].source_name : "unknown",
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
                if (var->memory_reference != 0) {
                    printf(" (Memory: 0x%08x)", var->memory_reference);
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

    uint32_t memory_reference = 0;
    uint32_t offset = 0;
    size_t instruction_offset = 0;
    size_t instruction_count = 10; // Default to 10 instructions
    bool resolve_symbols = false;
    bool memory_reference_set = false;

    // Parse command line arguments
    char* saveptr;
    char* token = strtok_r((char*)args, " ", &saveptr);
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

    if (!memory_reference_set) {
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
        fprintf(stderr, "Error: Client not initialized\n");
        return 1;
    }
    
    // Tokenize the arguments by commas
    // If no arguments, then use 'uncaught' as the default filter
    char* args_copy = args ? strdup(args) : strdup("uncaught");
    if (!args_copy) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        return 1;
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
        fprintf(stderr, "Error: Failed to allocate memory for filters\n");
        free(args_copy);
        return 1;
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
        fprintf(stderr, "Error setting exception breakpoints: %s\n", dap_error_message(error));
        free(args_copy);
        return 1;
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
    if (!client) return 1;

    int thread_id = 0;
    if (args && *args) {
        thread_id = atoi(args);
    }

    DAPPauseResult result = {0};
    DAPError error = dap_client_pause(client, thread_id, &result);

    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error pausing execution: %d\n", error);
        return 1;
    }

    printf("Execution paused\n");
    return 0;
}

int handle_evaluate_command(DAPClient* client, const char* args) {
    if (!client) return 1;

    if (!args || !*args) {
        fprintf(stderr, "Usage: evaluate <expression> [frame_id] [context]\n");
        return 1;
    }

    char* args_copy = strdup(args);
    if (!args_copy) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    char* expression = strtok(args_copy, " ");
    char* frame_str = strtok(NULL, " ");
    char* context = strtok(NULL, " ");

    int frame_id = frame_str ? atoi(frame_str) : 0;
    if (!context) {
        context = "repl";
    }

    DAPEvaluateResult result = {0};
    DAPError error = dap_client_evaluate(client, expression, frame_id, context, &result);

    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error evaluating expression: %d\n", error);
        free(args_copy);
        return 1;
    }

    printf("Result: %s", result.result ? result.result : "null");
    if (result.type) {
        printf(" (type: %s)", result.type);
    }
    printf("\n");

    free(args_copy);
    return 0;
}

int handle_launch_command(DAPClient* client, const char* args) {
    if (!client) return 1;

    const char* program_file = args;
    if (!program_file || !*program_file) {
        // Use the client's current program if no argument provided
        program_file = client->program_path;
    }

    if (!program_file || !*program_file) {
        fprintf(stderr, "Usage: launch <program_file>\n");
        return 1;
    }

    int error = dap_client_launch(client, program_file, true);

    if (error != DAP_ERROR_NONE) {
        fprintf(stderr, "Error launching program: %d\n", error);
        return 1;
    }

    printf("Program launched: %s\n", program_file);
    return 0;
}

int handle_read_memory_command(DAPClient* client, const char* args) {
    if (!client || !args || !*args) {
        printf("Usage: readMemory <memory_reference> [count] [offset]\n");
        printf("  memory_reference: Address (0x1000) or symbol (main)\n");
        printf("  count: Number of bytes to read (default: 16)\n");
        printf("  offset: Byte offset from address (default: 0)\n");
        printf("Examples:\n");
        printf("  readMemory 0x1000\n");
        printf("  readMemory main 64\n");
        printf("  readMemory 0x1000 32 8\n");
        return 1;
    }

    // Parse arguments: memory_reference [count] [offset]
    char* args_copy = strdup(args);
    if (!args_copy) return 1;

    char* memory_ref = strtok(args_copy, " ");
    char* count_str = strtok(NULL, " ");
    char* offset_str = strtok(NULL, " ");

    if (!memory_ref) {
        printf("Error: Memory reference required\n");
        free(args_copy);
        return 1;
    }

    int count = count_str ? atoi(count_str) : 16;  // Default 16 bytes
    int offset = offset_str ? atoi(offset_str) : 0; // Default offset 0

    // Validate parameters
    if (count <= 0 || count > 1024) {
        printf("Error: Count must be between 1 and 1024 bytes\n");
        free(args_copy);
        return 1;
    }

    if (offset < 0) {
        printf("Error: Offset must be non-negative\n");
        free(args_copy);
        return 1;
    }

    printf("Reading %d bytes from %s", count, memory_ref);
    if (offset > 0) {
        printf(" + %d", offset);
    }
    printf(":\n");

    // For now, we'll simulate memory reading since the DAP protocol support
    // for readMemory might not be implemented in all debug adapters
    printf("Memory dump at %s:\n", memory_ref);
    printf("Address   | Hex Values                      | ASCII\n");
    printf("----------|--------------------------------|--------\n");

    // Simulate some memory content for demonstration
    unsigned char sample_data[64];
    for (int i = 0; i < count && i < 64; i++) {
        sample_data[i] = (unsigned char)((i + offset) % 256);
    }

    // Display memory in hex dump format
    for (int i = 0; i < count; i += 16) {
        // Print address
        if (memory_ref[0] == '0' && memory_ref[1] == 'x') {
            // Hex address
            unsigned long addr = strtoul(memory_ref, NULL, 16);
            printf("%08lx  | ", addr + offset + i);
        } else {
            // Symbol name
            printf("%s+%04x | ", memory_ref, offset + i);
        }

        // Print hex values
        for (int j = 0; j < 16 && (i + j) < count; j++) {
            printf("%02x ", sample_data[i + j]);
        }

        // Pad if less than 16 bytes
        for (int j = i + ((count - i) > 16 ? 16 : (count - i)); j < i + 16; j++) {
            printf("   ");
        }

        printf("| ");

        // Print ASCII representation
        for (int j = 0; j < 16 && (i + j) < count; j++) {
            unsigned char c = sample_data[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }

        printf("\n");
    }

    printf("\nNote: This is simulated data. Real memory reading requires\n");
    printf("DAP server support for readMemory requests.\n");

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
