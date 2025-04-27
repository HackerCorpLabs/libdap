/**
 * @file dap_client_main.c
 * @brief Main entry point for the Debug Adapter Protocol client
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <cjson/cJSON.h>
#include "../libdap/include/dap_client.h"
#include "../libdap/include/dap_protocol.h"
#include "../libdap/include/dap_error.h"
#include <getopt.h>
#include <ctype.h>
#include <termios.h>
#include "dap_debugger_help.h"
#include "dap_debugger_ui.h"

// Move DAP event/command macros to the very top
#define DAP_CMD_STOPPED "stopped"
#define DAP_CMD_TERMINATED "terminated"
#define DAP_CMD_EXITED "exited"

#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT 4711

// Debug macro for raw JSON output. Undefine to disable raw JSON event/response printing.
#define DAP_DEBUG_PRINT_JSON

/*
 * When DAP_DEBUG_PRINT_JSON is defined, all received DAP events and responses
 * will be printed as raw JSON for debugging, in addition to pretty-printed output.
 * Undefine this macro for production or user-facing builds.
 */

// Add missing declarations
#define DAP_CLIENT_DEBUG_LOG(...) do { \
    fprintf(stderr, "DAP CLIENT: "); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
} while(0)

// Global client instance for signal handler
static DAPClient* g_client = NULL;
static const char* g_program_file = NULL;  // Store program file path

// Command history structure
typedef struct {
    char** commands;
    int capacity;
    int count;
    int current;
} CommandHistory;

// Initialize command history
static CommandHistory* history_create(int capacity) {
    CommandHistory* history = malloc(sizeof(CommandHistory));
    if (!history) return NULL;
    
    history->commands = calloc(capacity, sizeof(char*));
    if (!history->commands) {
        free(history);
        return NULL;
    }
    
    history->capacity = capacity;
    history->count = 0;
    history->current = -1;
    return history;
}

// Add command to history
static void history_add(CommandHistory* history, const char* command) {
    if (!history || !command) return;
    
    // Don't add empty commands or duplicates of the last command
    if (strlen(command) == 0 || 
        (history->count > 0 && strcmp(history->commands[history->count - 1], command) == 0)) {
        return;
    }
    
    // If history is full, remove oldest command
    if (history->count >= history->capacity) {
        free(history->commands[0]);
        memmove(history->commands, history->commands + 1, 
                (history->capacity - 1) * sizeof(char*));
        history->count--;
    }
    
    // Add new command
    history->commands[history->count++] = strdup(command);
    history->current = history->count;
}

// Get previous command from history
static const char* history_prev(CommandHistory* history) {
    if (!history || history->count == 0) return NULL;
    
    if (history->current > 0) {
        history->current--;
    }
    return history->commands[history->current];
}

// Get next command from history
static const char* history_next(CommandHistory* history) {
    if (!history || history->count == 0) return NULL;
    
    if (history->current < history->count - 1) {
        history->current++;
        return history->commands[history->current];
    }
    history->current = history->count;
    return "";
}

// Free command history
static void history_free(CommandHistory* history) {
    if (!history) return;
    
    for (int i = 0; i < history->count; i++) {
        free(history->commands[i]);
    }
    free(history->commands);
    free(history);
}

// Global command history
static CommandHistory* g_history = NULL;

// Add DAP client state enum at the top with other DAP-related definitions
typedef enum {
    DAP_CLIENT_STATE_INITIALIZED,
    DAP_CLIENT_STATE_RUNNING,
    DAP_CLIENT_STATE_STOPPED,
    DAP_CLIENT_STATE_TERMINATED
} DAPClientState;

// Add debug logging function
static void debug_log_message(const char* prefix, const char* message) {
    if (g_client) {
        fprintf(stderr, "[DAP DEBUG] %s: %s\n", prefix, message);
    }
}

static DAPThreadState parse_thread_state(const char* state) {
    if (!state) return DAP_THREAD_STATE_STOPPED;
    
    if (strcmp(state, "running") == 0) {
        return DAP_THREAD_STATE_RUNNING;
    } else if (strcmp(state, "stopped") == 0 || strcmp(state, "paused") == 0) {
        return DAP_THREAD_STATE_STOPPED;
    } else if (strcmp(state, "terminated") == 0) {
        return DAP_THREAD_STATE_TERMINATED;
    }
    // Only warn for truly unknown states
    if (strcmp(state, "paused") != 0) {
        fprintf(stderr, "Warning: Unknown thread state '%s', defaulting to STOPPED\n", state);
    }
    return DAP_THREAD_STATE_STOPPED;
}

/**
 * Handle shell commands
 */
static int handle_shell_command(const char* command, const char* arg) {
    if (strcmp(command, "debugmode") == 0) {
        if (g_client) {
            g_client->debug_mode = !g_client->debug_mode;
            printf("Debug mode %s\n", g_client->debug_mode ? "enabled" : "disabled");
        } else {
            printf("No client available\n");
        }
        return 0;
    } else if (strcmp(command, "threads") == 0) {
        DAPGetThreadsResult result = {0};
        int count = 0;
        int error = dap_client_get_threads(g_client, &result.threads, &count);
        if (error == DAP_ERROR_NONE) {
            result.num_threads = (size_t)count;
            printf("Threads:\n");
            for (int i = 0; i < count; i++) {
                printf("  Thread %d: %s", result.threads[i].id, result.threads[i].name);
                switch (result.threads[i].state) {
                    case DAP_THREAD_STATE_RUNNING:
                        printf(" (running)");
                        break;
                    case DAP_THREAD_STATE_STOPPED:
                        printf(" (stopped)");
                        break;
                    case DAP_THREAD_STATE_TERMINATED:
                        printf(" (terminated)");
                        break;
                    default:
                        printf(" (unknown)");
                        break;
                }
                printf("\n");
            }
            // Free thread names
            for (int i = 0; i < count; i++) {
                free(result.threads[i].name);
            }
            free(result.threads);
        } else {
            printf("Failed to get threads: %s\n", dap_error_message(error));
        }
        return 0;  // Return success even if thread listing failed
    } else if (strcmp(command, "pause") == 0) {
        if (!arg) {
            printf("Usage: pause <thread_id>\n");
            return -1;
        }
        int thread_id = atoi(arg);
        DAPPauseResult pause_result = {0};
        if (dap_client_pause(g_client, thread_id, &pause_result) == 0) {
            printf("Paused thread %d: %s\n", pause_result.thread_id, pause_result.reason);
            if (pause_result.all_threads_stopped) {
                printf("All threads stopped\n");
            }
        } else {
            printf("Failed to pause thread\n");
        }
    } else if (strcmp(command, "continue") == 0) {
        if (!arg) {
            printf("Usage: continue <thread_id>\n");
            return -1;
        }
        int thread_id = atoi(arg);
        DAPContinueResult continue_result = {0};
        if (dap_client_continue(g_client, thread_id, false, &continue_result) == 0) {
            printf("Continued thread %d\n", thread_id);
        }
    } else if (strcmp(command, "help") == 0) {
        // Safely parse the command line for help arguments
        char input_copy[256];
        strncpy(input_copy, command, sizeof(input_copy) - 1);
        input_copy[sizeof(input_copy) - 1] = '\0';
        char* saveptr = NULL;
        strtok_r(input_copy, " ", &saveptr); // "help"
        char* cmd_name = strtok_r(NULL, " ", &saveptr);    // next token, or NULL

        if (!cmd_name) {
            // No command name provided, show general help
            print_shell_help();
        } else {
            // Show help for specific command
            bool found = false;
            for (int i = 0; command_help[i].command_name; i++) {
                if (strcmp(command_help[i].command_name, cmd_name) == 0) {
                    printf("\nHelp for command '%s':\n", cmd_name);
                    printf("%s\n\n", str_repeat('=', strlen(cmd_name) + 16));
                    printf("Syntax:       %s\n", command_help[i].syntax);
                    printf("Description:  %s\n\n", command_help[i].description);
                    printf("Request format:\n%s\n\n", command_help[i].request_format);
                    printf("Response format:\n%s\n\n", command_help[i].response_format);
                    if (strcmp(command_help[i].events, "None") != 0 && 
                        strcmp(command_help[i].events, "N/A") != 0) {
                        printf("Events:\n%s\n\n", command_help[i].events);
                    }
                    printf("Example(s):\n%s\n", command_help[i].example);
                    found = true;
                    break;
                }
            }
            if (!found) {
                // Check if it's a valid command without detailed help
                for (int i = 0; commands[i].name; i++) {
                    if (strcmp(commands[i].name, cmd_name) == 0) {
                        printf("No detailed help available for command '%s'.\n", cmd_name);
                        found = true;
                        break;
                    }
                    if (commands[i].alias && strcmp(commands[i].alias, cmd_name) == 0) {
                        printf("No detailed help available for alias '%s' (command '%s').\n", 
                               cmd_name, commands[i].name);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    printf("Unknown command: '%s'\n", cmd_name);
                    printf("Type 'help' without arguments to see all available commands.\n");
                }
            }
        }
    } else if (strcmp(command, "initialize") == 0) {
        cJSON* args = cJSON_CreateObject();
        if (!args) return -1;
        
        cJSON_AddStringToObject(args, "clientID", "nd100x-debugger");
        cJSON_AddStringToObject(args, "clientName", "ND100X Debugger");
        cJSON_AddStringToObject(args, "adapterID", "nd100x");
        cJSON_AddStringToObject(args, "pathFormat", "path");
        cJSON_AddBoolToObject(args, "linesStartAt1", true);
        cJSON_AddBoolToObject(args, "columnsStartAt1", true);
        cJSON_AddBoolToObject(args, "supportsVariableType", true);
        cJSON_AddBoolToObject(args, "supportsVariablePaging", true);
        cJSON_AddBoolToObject(args, "supportsRunInTerminalRequest", false);
        cJSON_AddBoolToObject(args, "supportsMemoryReferences", true);

        char* response = NULL;
        if (dap_client_send_request(g_client, DAP_CMD_INITIALIZE, args, &response) == 0) {
            if (response) {
                printf("Initialize response: %s\n", response);
                free(response);
            }
        }
        cJSON_Delete(args);
    } else if (strcmp(command, "launch") == 0) {
        if (!g_program_file) {
            fprintf(stderr, "No program file specified\n");
            return -1;
        }

        cJSON* args = cJSON_CreateObject();
        if (!args) return -1;
        
        cJSON_AddStringToObject(args, "program", g_program_file);
        cJSON_AddBoolToObject(args, "stopOnEntry", true);
        cJSON_AddBoolToObject(args, "noDebug", false);

        char* response = NULL;
        if (dap_client_send_request(g_client, DAP_CMD_LAUNCH, args, &response) == 0) {
            if (response) {
                printf("Launch response: %s\n", response);
                free(response);
            }
        }
        cJSON_Delete(args);
    } else if (strcmp(command, "break") == 0 || strcmp(command, "b") == 0) {
        // Get next token if it exists
        const char* line = strtok(NULL, " ");
        
        if (!line) {
            // No parameters - list all breakpoints
            cJSON* args = cJSON_CreateObject();
            if (!args) return -1;
            
            // Add source file
            cJSON* source = cJSON_CreateObject();
            if (!source) {
                cJSON_Delete(args);
                return -1;
            }
            cJSON_AddStringToObject(source, "path", g_program_file);
            cJSON_AddItemToObject(args, "source", source);
            
            // Create empty breakpoints array to get current breakpoints
            cJSON* breakpoints = cJSON_CreateArray();
            if (!breakpoints) {
                cJSON_Delete(args);
                return -1;
            }
            cJSON_AddItemToObject(args, "breakpoints", breakpoints);

            char* response = NULL;
            if (dap_client_send_request(g_client, DAP_CMD_SET_BREAKPOINTS, args, &response) == 0) {
                if (response) {
                    cJSON* root = cJSON_Parse(response);
                    if (root) {
                        cJSON* body = cJSON_GetObjectItem(root, "body");
                        if (body) {
                            cJSON* bps = cJSON_GetObjectItem(body, "breakpoints");
                            if (bps && cJSON_IsArray(bps)) {
                                int count = cJSON_GetArraySize(bps);
                                if (count == 0) {
                                    printf("No breakpoints set\n");
                                } else {
                                    printf("Current breakpoints:\n");
                                    for (int i = 0; i < count; i++) {
                                        cJSON* bp = cJSON_GetArrayItem(bps, i);
                                        if (bp) {
                                            cJSON* line = cJSON_GetObjectItem(bp, "line");
                                            cJSON* verified = cJSON_GetObjectItem(bp, "verified");
                                            cJSON* message = cJSON_GetObjectItem(bp, "message");
                                            printf("  Line %d: %s (%s)\n", 
                                                   line ? line->valueint : 0,
                                                   verified ? (verified->valueint ? "verified" : "pending") : "unknown",
                                                   message ? message->valuestring : "");
                                        }
                                    }
                                }
                            }
                        }
                        cJSON_Delete(root);
                    }
                    free(response);
                }
            }
            cJSON_Delete(args);
            return 0;
        }

        // Parse line number
        int line_num = atoi(line);
        if (line_num <= 0) {
            fprintf(stderr, "Invalid line number\n");
            return -1;
        }

        cJSON* args = cJSON_CreateObject();
        if (!args) {
            return -1;
        }
        
        // Add source file
        cJSON* source = cJSON_CreateObject();
        if (!source) {
            cJSON_Delete(args);
            return -1;
        }
        cJSON_AddStringToObject(source, "path", g_program_file);
        cJSON_AddItemToObject(args, "source", source);
        
        // Create breakpoints array
        cJSON* breakpoints = cJSON_CreateArray();
        if (!breakpoints) {
            cJSON_Delete(args);
            return -1;
        }
        
        // Create breakpoint object
        cJSON* bp = cJSON_CreateObject();
        if (!bp) {
            cJSON_Delete(args);
            return -1;
        }
        cJSON_AddNumberToObject(bp, "line", line_num);
        cJSON_AddItemToArray(breakpoints, bp);
        
        cJSON_AddItemToObject(args, "breakpoints", breakpoints);

        char* response = NULL;
        if (dap_client_send_request(g_client, DAP_CMD_SET_BREAKPOINTS, args, &response) == 0) {
            if (response) {
                printf("Breakpoint set at line %d\n", line_num);
                free(response);
            }
        }
        cJSON_Delete(args);
        return 0;
    } else if (strcmp(command, "variables") == 0) {
        // Parse variables reference from argument
        int variables_reference = 0;
        if (arg) {
            variables_reference = atoi(arg);
            if (variables_reference <= 0) {
                printf("Invalid variables reference: %s\n", arg);
                return -1;
            }
        } else {
            // If no reference provided, get the current scope
            DAPGetScopesResult scopes_result = {0};
            int error = dap_client_get_scopes(g_client, 0, &scopes_result);
            if (error != DAP_ERROR_NONE) {
                printf("Error getting scopes: %d\n", error);
                return -1;
            }

            if (scopes_result.num_scopes == 0) {
                printf("No scopes available\n");
                dap_get_scopes_result_free(&scopes_result);
                return -1;
            }

            variables_reference = scopes_result.scopes[0].variables_reference;
            dap_get_scopes_result_free(&scopes_result);
        }

        // Get variables for the reference
        DAPGetVariablesResult result = {0};
        int error = dap_client_get_variables(g_client, variables_reference, 0, 0, &result);
        if (error != DAP_ERROR_NONE) {
            printf("Error getting variables: %d\n", error);
            return -1;
        }

        // Count simple variables and variables with children
        size_t simple_count = 0;
        size_t children_count = 0;
        for (size_t i = 0; i < result.num_variables; i++) {
            if (result.variables[i].variables_reference == 0) {
                simple_count++;
            } else {
                children_count++;
            }
        }

        printf("\nVariables (reference: %d)\n", variables_reference);
        
        // Print simple variables if any exist
        if (simple_count > 0) {
            printf("\nSimple Variables:\n");
            printf("┌──────────┬──────────┬──────────┐\n");
            printf("│ %-8s │ %-8s │ %-8s │\n", "Name", "Value", "Type");
            printf("├──────────┼──────────┼──────────┤\n");
            
            for (size_t i = 0; i < result.num_variables; i++) {
                DAPVariable* var = &result.variables[i];
                if (var->variables_reference == 0) {
                    printf("│ %-8s │ %-8s │ %-8s │\n", 
                           var->name, 
                           var->value,
                           var->type ? var->type : "");
                }
            }
            printf("└──────────┴──────────┴──────────┘\n");
        }
        
        // Print variables with children if any exist
        if (children_count > 0) {
            printf("\nVariables with Children:\n");
            printf("┌──────────┬──────────┬──────────┬──────────┬──────────┐\n");
            printf("│ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │\n", "Name", "Value", "Type", "Ref", "Children");
            printf("├──────────┼──────────┼──────────┼──────────┼──────────┤\n");
            
            for (size_t i = 0; i < result.num_variables; i++) {
                DAPVariable* var = &result.variables[i];
                if (var->variables_reference > 0) {
                    char children_info[32] = {0};
                    if (var->named_variables > 0) {
                        snprintf(children_info, sizeof(children_info), "named=%d", var->named_variables);
                    }
                    if (var->indexed_variables > 0) {
                        if (children_info[0]) strcat(children_info, ", ");
                        char temp[16];
                        snprintf(temp, sizeof(temp), "indexed=%d", var->indexed_variables);
                        strcat(children_info, temp);
                    }
                    
                    printf("│ %-8s │ %-8s │ %-8s │ %-8d │ %-8s │\n", 
                           var->name, 
                           var->value,
                           var->type ? var->type : "",
                           var->variables_reference,
                           children_info);
                }
            }
            printf("└──────────┴──────────┴──────────┴──────────┴──────────┘\n");
        }

        dap_get_variables_result_free(&result);
    } else if (strcmp(command, "scopes") == 0) {
        // Parse arguments if provided
        int frame_id_num = -1;
        
        if (arg) {
            char* arg_copy = strdup(arg);
            if (arg_copy) {
                char* saveptr = NULL;
                char* token = strtok_r(arg_copy, " ", &saveptr);
                
                // Parse frame ID if provided
                if (token) {
                    frame_id_num = atoi(token);
                    if (frame_id_num < 0) {
                        fprintf(stderr, "Invalid frame ID\n");
                        free(arg_copy);
                        return -1;
                    }
                }
                free(arg_copy);
            }
        }

        // Check if we have a valid thread ID and it's stopped
        if (!g_client || g_client->thread_id == -1) {
            fprintf(stderr, "No current thread available. The program must be stopped (at entry point, breakpoint, or after step).\n");
            return -1;
        }

        // Get thread state
        DAPThread* threads = NULL;
        int thread_count = 0;
        if (dap_client_get_threads(g_client, &threads, &thread_count) != 0) {
            fprintf(stderr, "Failed to get thread state\n");
            return -1;
        }

        bool thread_stopped = false;
        for (int i = 0; i < thread_count; i++) {
            if (threads[i].id == g_client->thread_id && 
                threads[i].state == DAP_THREAD_STATE_STOPPED) {
                thread_stopped = true;
                break;
            }
        }

        // Free thread names
        for (int i = 0; i < thread_count; i++) {
            free(threads[i].name);
        }
        free(threads);

        if (!thread_stopped) {
            fprintf(stderr, "Current thread is not stopped. The program must be stopped (at entry point, breakpoint, or after step).\n");
            return -1;
        }

        // If no frame ID provided, try to get current frame
        if (frame_id_num < 0) {
            DAPStackFrame* frames = NULL;
            int frame_count = 0;
            int error = dap_client_get_stack_trace(g_client, g_client->thread_id, &frames, &frame_count);
            
            if (error != DAP_ERROR_NONE || frame_count == 0) {
                // For assembly debugging, create a frame 0 if none exists
                frame_id_num = 0;
                printf("Using frame ID: 0 (entry point)\n");
            } else {
                // Use the top frame
                frame_id_num = frames[0].id;
                printf("Using current frame ID: %d\n", frame_id_num);
                
                // Clean up frames
                for (int i = 0; i < frame_count; i++) {
                    free(frames[i].name);
                    if (frames[i].source) {
                        free(frames[i].source->path);
                        free(frames[i].source);
                    }
                }
                free(frames);
            }
        }

        // Now get scopes for the frame
        DAPGetScopesResult result = {0};
        int scope_error = dap_client_get_scopes(g_client, frame_id_num, &result);

        if (scope_error == DAP_ERROR_NONE) {
            printf("\nScopes for frame %d:\n", frame_id_num);
            for (size_t i = 0; i < result.num_scopes; i++) {
                printf("  %s (ref: %d, vars: %d)%s\n", 
                       result.scopes[i].name,
                       result.scopes[i].variables_reference,
                       result.scopes[i].named_variables,
                       result.scopes[i].expensive ? " [expensive]" : "");
            }
            dap_get_scopes_result_free(&result);
        } else {
            fprintf(stderr, "Failed to get scopes: %s\n", dap_error_message(scope_error));
            return -1;
        }
    } else if (strcmp(command, "stack") == 0) {
        DAPThread* threads = NULL;
        int thread_count = 0;
        
        if (dap_client_get_threads(g_client, &threads, &thread_count) == 0) {
            for (int i = 0; i < thread_count; i++) {
                printf("Thread %d: %s", threads[i].id, threads[i].name);
                switch (threads[i].state) {
                    case DAP_THREAD_STATE_RUNNING:
                        printf(" (running)");
                        break;
                    case DAP_THREAD_STATE_STOPPED:
                        printf(" (stopped)");
                        break;
                    case DAP_THREAD_STATE_TERMINATED:
                        printf(" (terminated)");
                        break;
                    default:
                        printf(" (unknown)");
                        break;
                }
                printf("\n");

                DAPStackFrame* frames = NULL;
                int frame_count = 0;
                
                if (dap_client_get_stack_trace(g_client, threads[i].id, &frames, &frame_count)) {
                    for (int j = 0; j < frame_count; j++) {
                        printf("  Frame %d: %s at %s:%d\n", 
                               frames[j].id, 
                               frames[j].name,
                               frames[j].source ? frames[j].source->path : "unknown",
                               frames[j].line);
                    }
                    
                    // Free stack frames
                    for (int j = 0; j < frame_count; j++) {
                        free(frames[j].name);
                        if (frames[j].source) {
                            free(frames[j].source->path);
                            free(frames[j].source);
                        }
                    }
                    free(frames);
                }
            }
            
            // Free thread names
            for (int i = 0; i < thread_count; i++) {
                free(threads[i].name);
            }
            free(threads);
        } else {
            printf("Failed to get threads\n");
        }
        return 0;  // Return success even if thread listing failed
    } else if (strcmp(command, "quit") == 0 || strcmp(command, "q") == 0) {
        // Clean up and signal exit
        if (g_client) {
            DAPDisconnectResult result = {0};
            dap_client_disconnect(g_client, false, false, &result);
            dap_client_free(g_client);
            g_client = NULL;
        }
        return 1;  // Signal to exit
    } else if (strcmp(command, "clear") == 0) {
        // Clear breakpoint at specific line
        if (!g_program_file) {
            fprintf(stderr, "No program file specified\n");
            return -1;
        }

        // Get line number from command
        const char* line = strtok(NULL, " ");
        if (!line) {
            fprintf(stderr, "Missing line number\n");
            return -1;
        }

        int line_num = atoi(line);
        if (line_num <= 0) {
            fprintf(stderr, "Invalid line number\n");
            return -1;
        }

        // Create empty breakpoints array to clear all breakpoints
        cJSON* args = cJSON_CreateObject();
        if (!args) {
            return -1;
        }
        
        // Add source file
        cJSON* source = cJSON_CreateObject();
        if (!source) {
            cJSON_Delete(args);
            return -1;
        }
        cJSON_AddStringToObject(source, "path", g_program_file);
        cJSON_AddItemToObject(args, "source", source);
        
        // Create empty breakpoints array to clear all breakpoints
        cJSON* breakpoints = cJSON_CreateArray();
        if (!breakpoints) {
            cJSON_Delete(args);
            return -1;
        }
        cJSON_AddItemToObject(args, "breakpoints", breakpoints);

        char* response = NULL;
        if (dap_client_send_request(g_client, DAP_CMD_SET_BREAKPOINTS, args, &response) == 0) {
            if (response) {
                printf("Cleared all breakpoints\n");
                free(response);
            }
        }
        cJSON_Delete(args);
        return 0;

    } else if (strcmp(command, "clear-all") == 0) {
        // Clear all breakpoints
        if (!g_program_file) {
            fprintf(stderr, "No program file specified\n");
            return -1;
        }

        // Create empty breakpoints array to clear all breakpoints
        cJSON* args = cJSON_CreateObject();
        if (!args) {
            return -1;
        }
        
        // Add source file
        cJSON* source = cJSON_CreateObject();
        if (!source) {
            cJSON_Delete(args);
            return -1;
        }
        cJSON_AddStringToObject(source, "path", g_program_file);
        cJSON_AddItemToObject(args, "source", source);
        
        // Create empty breakpoints array to clear all breakpoints
        cJSON* breakpoints = cJSON_CreateArray();
        if (!breakpoints) {
            cJSON_Delete(args);
            return -1;
        }
        cJSON_AddItemToObject(args, "breakpoints", breakpoints);

        char* response = NULL;
        if (dap_client_send_request(g_client, DAP_CMD_SET_BREAKPOINTS, args, &response) == 0) {
            if (response) {
                printf("Cleared all breakpoints\n");
                free(response);
            }
        }
        cJSON_Delete(args);
        return 0;
    } else if (strcmp(command, "step-in") == 0) {
        // Validate debugger state
        if (!g_client) {
            fprintf(stderr, "No debugger client available\n");
            return -1;
        }

        // Get current thread state
        DAPThread* threads = NULL;
        int thread_count = 0;
        if (dap_client_get_threads(g_client, &threads, &thread_count) != 0) {
            fprintf(stderr, "Failed to get thread state\n");
            return -1;
        }

        // Find current thread and validate its state
        bool thread_found = false;
        bool thread_stopped = false;
        for (int i = 0; i < thread_count; i++) {
            if (threads[i].id == g_client->thread_id) {
                thread_found = true;
                thread_stopped = (threads[i].state == DAP_THREAD_STATE_STOPPED);
                break;
            }
        }

        // Clean up thread data
        for (int i = 0; i < thread_count; i++) {
            free(threads[i].name);
        }
        free(threads);

        if (!thread_found) {
            fprintf(stderr, "Current thread not found\n");
            return -1;
        }

        if (!thread_stopped) {
            fprintf(stderr, "Cannot step in: thread is not stopped\n");
            return -1;
        }

        // Parse optional arguments
        const char* target_id = NULL;
        const char* granularity = NULL;
        bool single_thread = false;

        if (arg) {
            char* arg_copy = strdup(arg);
            if (arg_copy) {
                char* saveptr = NULL;
                char* token = strtok_r(arg_copy, " ", &saveptr);
                
                while (token) {
                    if (strcmp(token, "--single-thread") == 0) {
                        single_thread = true;
                    } else if (strncmp(token, "--target=", 9) == 0) {
                        target_id = token + 9;
                    } else if (strncmp(token, "--granularity=", 14) == 0) {
                        granularity = token + 14;
                    }
                    token = strtok_r(NULL, " ", &saveptr);
                }
                free(arg_copy);
            }
        }

        // Execute step-in command
        DAPStepInResult result = {0};
        int error = dap_client_step_in(
            g_client,
            g_client->thread_id,
            target_id,
            granularity,
            &result
        );
        
        if (error == DAP_ERROR_NONE) {
            printf("Stepped in successfully\n");
            if (result.all_threads_stopped) {
                printf("All threads stopped\n");
            }
        } else {
            fprintf(stderr, "Failed to step in: %s\n", dap_error_message(error));
            return -1;
        }

        return 0;
    } else if (strcmp(command, "step-out") == 0) {
        int thread_id = g_client->thread_id;
        DAPStepOutResult result = {0};
        if (dap_client_step_out(g_client, thread_id, &result) == 0) {
            printf("Stepped out successfully\n");
            if (result.all_threads_stopped) printf("All threads stopped\n");
        } else {
            printf("Failed to step out\n");
        }
        return 0;
    } else if (strcmp(command, "step-back") == 0) {
        int thread_id = g_client->thread_id;
        DAPStepBackResult result = {0};
        if (dap_client_step_back(g_client, thread_id, &result) == 0) {
            printf("Stepped back successfully\n");
            if (result.all_threads_stopped) printf("All threads stopped\n");
        } else {
            printf("Failed to step back\n");
        }
        return 0;
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
    }

    return 0;
}

void handle_signal(int sig) {
    extern DAPClient* g_client;
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\nReceived signal %d, shutting down...\n", sig);
        if (g_client) {
            DAPDisconnectResult result = {0};
            dap_client_disconnect(g_client, false, false, &result);
            dap_client_free(g_client);
            g_client = NULL;  // Set to NULL after freeing
        }
        exit(EXIT_SUCCESS);
    }
} 


/**
 * Main entry point
 */
int main(int argc, char* argv[]) {
    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Set terminal to raw mode for unbuffered input
    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~(ICANON | ECHO);  // Disable canonical mode and echo
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
    
    // Parse command line arguments
    const char* program_file = NULL;
    const char* host = DEFAULT_HOST;
    int port = DEFAULT_PORT;
    bool stop_at_entry = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-e") == 0) {
            stop_at_entry = true;
        } else {
            program_file = argv[i];
        }
    }
    
    if (!program_file) {
        print_usage(argv[0]);
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        return 1;
    }
    
    g_program_file = program_file;  // Store program file path
    
    // Create client
    g_client = dap_client_create(host, port);
    if (!g_client) {
        fprintf(stderr, "Failed to create DAP client\n");
        return 1;
    }
    
    // Connect to server
    if (dap_client_connect(g_client) != 0) {
        fprintf(stderr, "Failed to connect to DAP server\n");
        dap_client_free(g_client);
        g_client = NULL;
        return 1;
    }
    
    // Initialize debug session
    if (dap_client_initialize(g_client) != 0) {
        fprintf(stderr, "Failed to initialize debug session\n");
        DAPDisconnectResult result = {0};
        dap_client_disconnect(g_client, false, false, &result);
        dap_client_free(g_client);
        g_client = NULL;
        return 1;
    }
    
    // Get initial thread list
    DAPThread* threads = NULL;
    int num_threads = 0;
    if (dap_client_get_threads(g_client, &threads, &num_threads) != 0) {
        printf("Failed to get initial thread list\n");
        dap_client_free(g_client);
        g_client = NULL;
        return 1;
    }
    
    // Set initial thread ID if we have threads
    if (threads && num_threads > 0) {
        g_client->thread_id = threads[0].id;
    }
    
    // Free threads
    if (threads) {
        for (int i = 0; i < num_threads; i++) {
            free(threads[i].name);
        }
        free(threads);
    }
    
    // Launch program
    if (dap_client_launch(g_client, program_file, stop_at_entry) != 0) {
        fprintf(stderr, "Failed to launch program\n");
        DAPDisconnectResult result = {0};
        dap_client_disconnect(g_client, false, false, &result);
        dap_client_free(g_client);
        g_client = NULL;
        return 1;
    }
    
    // Create command history
    g_history = history_create(100);
    if (!g_history) {
        fprintf(stderr, "Failed to create command history\n");
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        return 1;
    }
    
    // Main command loop
    printf("\nDAP Debugger Shell\n");
    printf("Type 'help' for available commands\n\n");
    
    char cmd[256];
    int cmd_len = 0;
    int cursor_pos = 0;
    
    fd_set read_fds;
    int max_fd;
    struct timeval timeout;
    
    while (g_client->connected) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(g_client->fd, &read_fds);
        max_fd = (STDIN_FILENO > g_client->fd) ? STDIN_FILENO : g_client->fd;
        
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; // 100ms timeout
        
        int ready = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            perror("select");
            break;
        }
        
        if (FD_ISSET(g_client->fd, &read_fds)) {
            cJSON* message = NULL;
            if (dap_client_receive_message(g_client, &message) == 0) {
                if (message) {
                    // Process the message
                    const char* command = cJSON_GetStringValue(cJSON_GetObjectItem(message, "command"));
                    if (command) {
                        if (strcmp(command, DAP_CMD_STOPPED) == 0) {
                            // Handle stopped event
                            cJSON* body = cJSON_GetObjectItem(message, "body");
                            if (body) {
                                cJSON* reason = cJSON_GetObjectItem(body, "reason");
                                cJSON* thread_id = cJSON_GetObjectItem(body, "threadId");
                                cJSON* all_threads_stopped = cJSON_GetObjectItem(body, "allThreadsStopped");
                                
                                if (reason && cJSON_IsString(reason)) {
                                    printf("\nProgram stopped: %s\n", reason->valuestring);
                                }
                                
                                if (thread_id && cJSON_IsNumber(thread_id)) {
                                    g_client->thread_id = thread_id->valueint;
                                    printf("Thread ID: %d\n", thread_id->valueint);
                                }
                                
                                if (all_threads_stopped && cJSON_IsBool(all_threads_stopped)) {
                                    printf("All threads stopped: %s\n", 
                                          all_threads_stopped->valueint ? "yes" : "no");
                                }
                                
                                // Get stack trace for the stopped thread
                                DAPStackFrame* frames = NULL;
                                int frame_count = 0;
                                if (dap_client_get_stack_trace(g_client, g_client->thread_id, &frames, &frame_count) == 0) {
                                    printf("\nStack trace:\n");
                                    for (int i = 0; i < frame_count; i++) {
                                        printf("#%d %s:%d\n", i, frames[i].name, frames[i].line);
                                        free(frames[i].name);
                                    }
                                    free(frames);
                                }
                            }
                        } else if (strcmp(command, DAP_CMD_TERMINATED) == 0) {
                            printf("\nDebug session terminated\n");
                            break;
                        } else if (strcmp(command, DAP_CMD_EXITED) == 0) {
                            cJSON* body = cJSON_GetObjectItem(message, "body");
                            if (body) {
                                cJSON* exit_code = cJSON_GetObjectItem(body, "exitCode");
                                if (exit_code && cJSON_IsNumber(exit_code)) {
                                    printf("\nProgram exited with code %d\n", exit_code->valueint);
                                }
                            }
                            break;
                        }
                    }
                    cJSON_Delete(message);
                }
            } else {
                printf("Error receiving message\n");
                break;
            }
        }
        
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            // Display prompt
            printf("(dap) ");
            fflush(stdout);
            
            cmd_len = 0;
            cursor_pos = 0;
            memset(cmd, 0, sizeof(cmd));
            
            while (1) {
                char c;
                if (read(STDIN_FILENO, &c, 1) != 1) {
                    continue;
                }
                
                // Handle arrow keys and special characters
                if (c == '\x1b') {  // ESC sequence
                    char seq[2];
                    if (read(STDIN_FILENO, &seq[0], 1) != 1) continue;
                    if (read(STDIN_FILENO, &seq[1], 1) != 1) continue;
                    
                    if (seq[0] == '[') {
                        switch (seq[1]) {
                            case 'A':  // Up arrow
                                if (g_history) {
                                    const char* prev_cmd = history_prev(g_history);
                                    if (prev_cmd) {
                                        strncpy(cmd, prev_cmd, sizeof(cmd) - 1);
                                        cmd_len = strlen(cmd);
                                        cursor_pos = cmd_len;
                                        print_command_with_cursor(cmd, cursor_pos);
                                    }
                                }
                                continue;
                            case 'B':  // Down arrow
                                if (g_history) {
                                    const char* next_cmd = history_next(g_history);
                                    if (next_cmd) {
                                        strncpy(cmd, next_cmd, sizeof(cmd) - 1);
                                        cmd_len = strlen(cmd);
                                        cursor_pos = cmd_len;
                                        print_command_with_cursor(cmd, cursor_pos);
                                    }
                                }
                                continue;
                            case 'C':  // Right arrow
                                if (cursor_pos < cmd_len) {
                                    cursor_pos++;
                                    print_command_with_cursor(cmd, cursor_pos);
                                }
                                continue;
                            case 'D':  // Left arrow
                                if (cursor_pos > 0) {
                                    cursor_pos--;
                                    print_command_with_cursor(cmd, cursor_pos);
                                }
                                continue;
                        }
                    }
                    continue;
                }
                
                if (c == '\n') {
                    printf("\n");
                    break;
                }
                if (c == '\t') {
                    handle_tab_completion(cmd, &cursor_pos);
                    cmd_len = strlen(cmd);
                    print_command_with_cursor(cmd, cursor_pos);
                    continue;
                }
                if (c == 127 || c == 8) {  // Backspace
                    if (cursor_pos > 0) {
                        memmove(cmd + cursor_pos - 1, cmd + cursor_pos, 
                                cmd_len - cursor_pos + 1);
                        cursor_pos--;
                        cmd_len--;
                        print_command_with_cursor(cmd, cursor_pos);
                    }
                    continue;
                }
                
                // Handle regular input
                if (cmd_len < (int)(sizeof(cmd) - 1)) {
                    memmove(cmd + cursor_pos + 1, cmd + cursor_pos, 
                            cmd_len - cursor_pos + 1);
                    cmd[cursor_pos] = c;
                    cursor_pos++;
                    cmd_len++;
                    print_command_with_cursor(cmd, cursor_pos);
                }
            }
            
            // Process command
            if (cmd_len > 0) {
                history_add(g_history, cmd);
                
                // Split command into command name and arguments
                char* cmd_copy = strdup(cmd);
                if (cmd_copy) {
                    char* saveptr = NULL;
                    char* command = strtok_r(cmd_copy, " ", &saveptr);
                    char* args = strtok_r(NULL, "", &saveptr);  // Get rest of string as args
                    
                    handle_shell_command(command, args);
                    free(cmd_copy);
                }
            }
        }
    }
    
    // Cleanup
    if (g_history) {
        history_free(g_history);
        g_history = NULL;  // Set to NULL after freeing
    }
    
    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    
    // Cleanup client
    if (g_client) {
        DAPDisconnectResult result = {0};
        dap_client_disconnect(g_client, false, false, &result);
        dap_client_free(g_client);
        g_client = NULL;  // Set to NULL after freeing
    }
    
    return 0;
}

// Add a new helper function to print JSON if debug is enabled
__attribute__((unused)) static void dap_print_json_if_debug(const char* json) {
#ifdef DAP_DEBUG_PRINT_JSON
    if (json) {
        fprintf(stderr, "[DAP RAW JSON]: %s\n", json);
    }
#endif
}

