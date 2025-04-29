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
#include <sys/select.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <cjson/cJSON.h>
#include "../libdap/include/dap_client.h"
#include "../libdap/include/dap_protocol.h"
#include "../libdap/include/dap_error.h"
#include <getopt.h>
#include <ctype.h>
#include <termios.h>
#include <strings.h>  /* for strcasecmp */
#include "dap_debugger_help.h"
#include "dap_debugger_ui.h"
#include "dap_debugger_types.h"
#include "dap_debugger_main.h"

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

// Debugger states
typedef enum {
    DAP_DEBUGGER_STATE_INITIAL,
    DAP_DEBUGGER_STATE_CONNECTED,
    DAP_DEBUGGER_STATE_INITIALIZED,
    DAP_DEBUGGER_STATE_LAUNCHED,
    DAP_DEBUGGER_STATE_RUNNING,
    DAP_DEBUGGER_STATE_STOPPED,
    DAP_DEBUGGER_STATE_TERMINATED,
    DAP_DEBUGGER_STATE_ERROR
} DAPDebuggerState;

// Debugger context structure
typedef struct {
    DAPClient* client;
    DAPDebuggerState state;
    const char* program_file;
    bool stop_at_entry;
    CommandHistory* history;
    struct termios old_term;
} DAPDebuggerContext;


/**
 * Handle shell commands
 */
static int handle_shell_command(const char* command, const char* arg) {
    if (!command) return 0;

    // Find the command in our table (case-insensitive)
    const DebuggerCommand* cmd = find_command(command);
    if (!cmd) {
        fprintf(stderr, "Unknown command: %s\n", command);
        fprintf(stderr, "Type 'help' for a list of available commands\n");
        return 0;
    }

    // Use the canonical command name for execution
    command = cmd->name;

    // Call the command handler if it exists
    if (cmd->handler) {
        return cmd->handler(g_client, arg);
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
    cJSON* program_args = NULL;
    cJSON* env_vars = NULL;
    const char* working_dir = NULL;
    
    // Define long options
    struct option long_options[] = {
        {"host", required_argument, 0, 'h'},
        {"port", required_argument, 0, 'p'},
        {"stop-on-entry", no_argument, 0, 'e'},
        {"program", required_argument, 0, 'f'},
        {"args", required_argument, 0, 'a'},
        {"env", required_argument, 0, 'v'},
        {"cwd", required_argument, 0, 'd'},
        {"help", no_argument, 0, '?'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "h:p:ef:a:v:d:?", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                host = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'e':
                stop_at_entry = true;
                break;
            case 'f':
                program_file = optarg;
                break;
            case 'a': {
                // Parse program arguments - comma-separated list
                program_args = cJSON_CreateArray();
                char* args_copy = strdup(optarg);
                char* token = strtok(args_copy, ",");
                while (token) {
                    cJSON_AddItemToArray(program_args, cJSON_CreateString(token));
                    token = strtok(NULL, ",");
                }
                free(args_copy);
                break;
            }
            case 'v': {
                // Parse environment variables - comma-separated list of name=value pairs
                env_vars = cJSON_CreateObject();
                char* env_copy = strdup(optarg);
                char* token = strtok(env_copy, ",");
                while (token) {
                    char* equals = strchr(token, '=');
                    if (equals) {
                        *equals = '\0';
                        cJSON_AddStringToObject(env_vars, token, equals + 1);
                    }
                    token = strtok(NULL, ",");
                }
                free(env_copy);
                break;
            }
            case 'd':
                working_dir = optarg;
                break;
            case '?':
                print_usage(argv[0]);
                tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
                if (program_args) cJSON_Delete(program_args);
                if (env_vars) cJSON_Delete(env_vars);
                return 0;
            default:
                print_usage(argv[0]);
                tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
                if (program_args) cJSON_Delete(program_args);
                if (env_vars) cJSON_Delete(env_vars);
                return 1;
        }
    }
    
    // Check for positional program argument (backward compatibility)
    if (optind < argc && !program_file) {
        program_file = argv[optind];
    }
    
    if (!program_file) {
        print_usage(argv[0]);
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        if (program_args) cJSON_Delete(program_args);
        if (env_vars) cJSON_Delete(env_vars);
        return 1;
    }
    
    g_program_file = program_file;  // Store program file path
    
    // Create client
    g_client = dap_client_create(host, port);
    if (!g_client) {
        fprintf(stderr, "Failed to create DAP client\n");
        if (program_args) cJSON_Delete(program_args);
        if (env_vars) cJSON_Delete(env_vars);
        return 1;
    }
    
    // Store program path in client for future reference
    g_client->program_path = strdup(program_file);
    
    // Set shorter timeout value (5 seconds instead of default 30)
    g_client->timeout_ms = 5000;
    
    // Connect to server
    if (dap_client_connect(g_client) != 0) {
        fprintf(stderr, "Failed to connect to DAP server\n");
        dap_client_free(g_client);
        g_client = NULL;
        if (program_args) cJSON_Delete(program_args);
        if (env_vars) cJSON_Delete(env_vars);
        return 1;
    }
    
    // Initialize debug session
    if (dap_client_initialize(g_client) != 0) {
        fprintf(stderr, "Failed to initialize debug session\n");
        DAPDisconnectResult result = {0};
        dap_client_disconnect(g_client, false, false, &result);
        dap_client_free(g_client);
        g_client = NULL;
        if (program_args) cJSON_Delete(program_args);
        if (env_vars) cJSON_Delete(env_vars);
        return 1;
    }
    
    // Get initial thread list
    DAPThread* threads = NULL;
    int num_threads = 0;
    if (dap_client_get_threads(g_client, &threads, &num_threads) != 0) {
        printf("Failed to get initial thread list\n");
        dap_client_free(g_client);
        g_client = NULL;
        if (program_args) cJSON_Delete(program_args);
        if (env_vars) cJSON_Delete(env_vars);
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
    
    // Create a launch arguments JSON object
    cJSON* launch_args = cJSON_CreateObject();
    if (!launch_args) {
        fprintf(stderr, "Failed to create launch arguments\n");
        DAPDisconnectResult result = {0};
        dap_client_disconnect(g_client, false, false, &result);
        dap_client_free(g_client);
        g_client = NULL;
        if (program_args) cJSON_Delete(program_args);
        if (env_vars) cJSON_Delete(env_vars);
        return 1;
    }
    
    // Add required parameters
    cJSON_AddStringToObject(launch_args, "program", program_file);
    cJSON_AddBoolToObject(launch_args, "stopOnEntry", stop_at_entry);
    cJSON_AddBoolToObject(launch_args, "noDebug", false);
    
    // Add optional parameters if provided
    if (program_args) {
        cJSON_AddItemToObject(launch_args, "args", program_args);
    }
    
    if (env_vars) {
        cJSON_AddItemToObject(launch_args, "env", env_vars);
    }
    
    if (working_dir) {
        cJSON_AddStringToObject(launch_args, "cwd", working_dir);
        printf("Setting working directory to: %s\n", working_dir);
    }
    
    // Send the launch request with all parameters
    char* response = NULL;
    if (dap_client_send_request(g_client, DAP_CMD_LAUNCH, launch_args, &response) != 0) {
        fprintf(stderr, "Failed to launch program\n");
        cJSON_Delete(launch_args);
        DAPDisconnectResult result = {0};
        dap_client_disconnect(g_client, false, false, &result);
        dap_client_free(g_client);
        g_client = NULL;
        return 1;
    }
    
    if (response) {
        // Print launch response if in debug mode
        if (g_client->debug_mode) {
            printf("Launch response: %s\n", response);
        }
        free(response);
    }
    
    // Clean up launch_args (program_args and env_vars are now owned by launch_args)
    cJSON_Delete(launch_args);
    
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
            if (errno == EINTR) {
                // If interrupted by signal, just continue
                continue;
            }
            perror("select");
            break;
        }
        
        if (FD_ISSET(g_client->fd, &read_fds)) {
            cJSON* message = NULL;
            int recv_result = dap_client_receive_message(g_client, &message);
            
            if (recv_result == 0) {
                if (message) {
                    // Process the message
                    const char* type = cJSON_GetStringValue(cJSON_GetObjectItem(message, "type"));
                    if (type && strcmp(type, "event") == 0) {
                        const char* event = cJSON_GetStringValue(cJSON_GetObjectItem(message, "event"));
                        if (event) {
                            if (strcmp(event, DAP_CMD_STOPPED) == 0) {
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
                                            if (frames[i].source) {
                                                free(frames[i].source->path);
                                                free(frames[i].source);
                                            }
                                        }
                                        free(frames);
                                    }
                                }
                            } else if (strcmp(event, DAP_CMD_TERMINATED) == 0) {
                                printf("\nDebug session terminated\n");
                                break;
                            } else if (strcmp(event, DAP_CMD_EXITED) == 0) {
                                cJSON* body = cJSON_GetObjectItem(message, "body");
                                if (body) {
                                    cJSON* exit_code = cJSON_GetObjectItem(body, "exitCode");
                                    if (exit_code && cJSON_IsNumber(exit_code)) {
                                        printf("\nProgram exited with code %d\n", exit_code->valueint);
                                    } else {
                                        printf("\nProgram exited (unknown exit code)\n");
                                    }
                                } else {
                                    printf("\nProgram exited\n");
                                }
                                break;
                            } else {
                                // Handle other events - print for debugging
                                #ifdef DAP_DEBUG_PRINT_JSON
                                char* json_str = cJSON_Print(message);
                                if (json_str) {
                                    printf("\nReceived event: %s\n", event);
                                    printf("Event details: %s\n", json_str);
                                    free(json_str);
                                }
                                #else
                                printf("\nReceived event: %s\n", event);
                                #endif
                            }
                        }
                    } else if (type && strcmp(type, "response") == 0) {
                        // Process responses when they arrive
                        // This is needed to handle responses to requests sent from within the event loop
                        const char* command_str = cJSON_GetStringValue(cJSON_GetObjectItem(message, "command"));
                        if (command_str) {
                            // Log received response for debugging if needed
                            #ifdef DAP_DEBUG_PRINT_JSON
                            char* json_str = cJSON_Print(message);
                            if (json_str) {
                                printf("\nReceived response for command: %s\n", command_str);
                                printf("Response details: %s\n", json_str);
                                free(json_str);
                            }
                            #endif
                            
                            // Handle specific responses if needed
                            // For now we just acknowledge receipt of the response and continue
                            if (g_client->debug_mode) {
                                printf("\nReceived response for command: %s\n", command_str);
                            }
                        }
                    }
                    
                    cJSON_Delete(message);
                }
            } else if (recv_result == DAP_ERROR_TIMEOUT) {
                // Handle timeout gracefully - don't break out of the main loop
                printf("\nTimeout waiting for server response\n");
            } else {
                // Any other non-zero result is an error
                printf("\nError receiving message: %d (%s)\n", 
                       recv_result, dap_error_message(recv_result));
                if (g_client && !g_client->connected) {
                    printf("Connection closed by server\n");
                }
                break;
            }
        }
        
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {

            cmd_len = 0;
            cursor_pos = 0;
            memset(cmd, 0, sizeof(cmd));
            
            while (1) {
                char c;
                if (read(STDIN_FILENO, &c, 1) != 1) {
                    if (errno == EINTR) continue;
                    break;
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
                    
                    // Check if the just-typed character is "?" at the end of a command
                    if (c == '?' && cursor_pos > 1) {
                        // Check if the position before ? is a space (indicating "command ?")
                        if (cmd[cursor_pos-2] == ' ') {
                            // Tokenize the command for processing
                            char* cmd_copy = strdup(cmd);
                            if (cmd_copy) {
                                // Split into command name
                                char* saveptr = NULL;
                                char* command = strtok_r(cmd_copy, " ", &saveptr);
                                
                                // Show parameter help immediately
                                if (command) {
                                    printf("\n"); // Move to a new line
                                    print_parameter_help(command);
                                    
                                    // Show prompt and command again
                                    printf("\n(dap6) ");
                                    print_command_with_cursor(cmd, cursor_pos);
                                }
                                free(cmd_copy);
                            }
                        }
                    }
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
                    
                    // Check if this is a parameter help request (command ?)
                    if (args && *args) {
                        // Trim leading whitespace
                        while (*args && isspace(*args)) args++;
                        
                        // Check if args is just "?"
                        if (strcmp(args, "?") == 0) {
                            int result = print_parameter_help(command);
                            free(cmd_copy);  // Free the copy before continuing
                            if (result == 1) {
                                continue;  // Skip normal command processing
                            }
                        }
                    }
                    
                    int result = handle_shell_command(command, args);
                    free(cmd_copy);  // Free the copy after command processing
                    if (result == 1) {
                        break;  // Exit command loop
                    }
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
        if (g_client->program_path) {
            free(g_client->program_path);
            g_client->program_path = NULL;
        }
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

/**
 * @brief Print parameter help for a command
 * 
 * This function displays help information about parameters for a specific command.
 * It's triggered when the user enters "command ?" in the shell.
 * 
 * @param command_name The name of the command to show parameter help for
 * @return int 1 if command was found and help was displayed, 0 otherwise
 */
int print_parameter_help(const char* command_name) {
    const DebuggerCommand* cmd = find_command(command_name);
    if (!cmd) {
        printf("Unknown command: %s\n", command_name);
        return 0;
    }

    if (!cmd->has_options) {
        printf("No parameters available for command '%s'\n", command_name);
        return 1;
    }

    // Print parameter information
    if (cmd->option_types && cmd->option_descriptions) {
        char* types = strdup(cmd->option_types);
        char* descs = strdup(cmd->option_descriptions);
        char* type_token = strtok(types, "|");
        char* desc_token = strtok(descs, "|");
        
        printf("\nParameters for '%s':\n", command_name);
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
    
    return 1;
}

