#include "dap_debugger_threads.h"
#include "dap_debugger_ui.h"
#include "dap_debugger_commands.h"
#include "dap_debugger_help.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/select.h>
#include <poll.h>
#include <errno.h>
#include <ctype.h>
#include <strings.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <signal.h>

#define DAP_PROMPT "dap# "

// Forward declarations
static bool process_user_input(DAPThreadContext* ctx, const char* input);
static void handle_ui_events(DAPThreadContext* ctx);
static void setup_terminal(void);
static void restore_terminal(void);

static struct termios original_termios;
static bool terminal_setup = false;

/**
 * Main UI thread function
 * Handles:
 * 1. Non-blocking user input with readline
 * 2. Event processing from DAP thread
 * 3. Display updates and prompt management
 */
void* dap_ui_thread_main(void* arg) {
    DAPThreadContext* ctx = (DAPThreadContext*)arg;
    if (!ctx) {
        fprintf(stderr, "UI thread: No context provided\n");
        return NULL;
    }

    printf("UI thread started\n");
    printf("Type 'help' for available commands, 'exit' to quit\n");

    setup_terminal();

    // Show initial prompt
    printf(DAP_PROMPT);
    fflush(stdout);

    // Main UI loop - static variables for input handling
    static char input_buffer[1024];
    static int buffer_pos = 0;
    static bool need_prompt = false;

    while (!dap_thread_context_is_shutdown_requested(ctx)) {
        // Process events first
        handle_ui_events(ctx);

        // Check for shutdown
        if (dap_thread_context_is_shutdown_requested(ctx)) {
            break;
        }

        // Check for DAP events first (non-blocking)
        struct pollfd event_fd = {ctx->event_notify_fd, POLLIN, 0};
        int event_ready = poll(&event_fd, 1, 0); // Non-blocking check

        if (event_ready > 0 && (event_fd.revents & POLLIN)) {
            // Clear the eventfd notification
            uint64_t value;
            read(ctx->event_notify_fd, &value, sizeof(value));
        }

        // Show prompt if needed (after events are processed)
        if (need_prompt) {
            printf(DAP_PROMPT);
            fflush(stdout);
            need_prompt = false;
        }

        // Use select + read for both interactive and non-interactive
        fd_set read_fds;
        struct timeval timeout;
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        timeout.tv_sec = 0;
        timeout.tv_usec = 200000; // 200ms

        int ready = select(STDIN_FILENO + 1, &read_fds, NULL, NULL, &timeout);

        if (ready > 0 && FD_ISSET(STDIN_FILENO, &read_fds)) {
            char c;
            ssize_t bytes_read = read(STDIN_FILENO, &c, 1);

            if (bytes_read <= 0) {
                // EOF or error
                dap_thread_context_request_shutdown(ctx);
                break;
            }

            if (c == '\n' || c == '\r') {
                // End of line
                input_buffer[buffer_pos] = '\0';
                printf("\n");

                if (buffer_pos > 0) {
                    bool was_local_command = process_user_input(ctx, input_buffer);
                    buffer_pos = 0;

                    // Only show prompt immediately for local commands
                    // For DAP commands, prompt will be shown after response
                    if (was_local_command) {
                        need_prompt = true;
                    }
                } else {
                    // Empty command, show prompt
                    need_prompt = true;
                }
            } else if (c == '\b' || c == 127) { // Backspace or DEL
                if (buffer_pos > 0) {
                    buffer_pos--;
                    printf("\b \b");
                    fflush(stdout);
                }
            } else if (c >= 32 && c <= 126) { // Printable characters
                if (buffer_pos < sizeof(input_buffer) - 1) {
                    input_buffer[buffer_pos++] = c;
                    printf("%c", c);
                    fflush(stdout);
                }
            }
            // Ignore other control characters
        }
    }

    restore_terminal();
    printf("UI thread exiting\n");
    return NULL;
}

static bool process_user_input(DAPThreadContext* ctx, const char* input) {
    if (!ctx || !input) return true;

    // Skip empty input
    char* trimmed = strdup(input);
    if (!trimmed) return true;

    // Trim whitespace
    char* start = trimmed;
    while (*start && isspace(*start)) start++;
    if (!*start) {
        free(trimmed);
        return true;
    }

    char* end = start + strlen(start) - 1;
    while (end > start && isspace(*end)) *end-- = '\0';

    // Parse command and arguments
    char* space = strchr(start, ' ');
    char* command_name = start;
    char* args = NULL;

    if (space) {
        *space = '\0';
        args = space + 1;
        // Trim leading spaces from args
        while (*args && isspace(*args)) args++;
        if (!*args) args = NULL;
    }


    // Handle local commands immediately in UI thread for responsiveness
    if (strcasecmp(command_name, "help") == 0) {
        if (args && *args) {
            print_command_help(args);
        } else {
            print_shell_help();
        }
        free(trimmed);
        return true;
    }

    if (strcasecmp(command_name, "unsupported") == 0) {
        print_unsupported_commands();
        free(trimmed);
        return true;
    }

    if (strcasecmp(command_name, "capabilities") == 0 || strcasecmp(command_name, "srv") == 0 || strcasecmp(command_name, "server") == 0) {
        handle_capabilities_command(ctx->client, args);
        free(trimmed);
        return true;
    }

    if (strcasecmp(command_name, "exit") == 0 || strcasecmp(command_name, "quit") == 0) {
        dap_thread_context_request_shutdown(ctx);
        printf("Exiting debugger\n");
        free(trimmed);
        return true;
    }

    if (strcasecmp(command_name, "status") == 0) {
        pthread_mutex_lock(&ctx->state_mutex);
        printf("UI Thread: Running\n");
        printf("Connected: %s\n", ctx->connected ? "yes" : "no");
        printf("Debuggee Running: %s\n", ctx->debuggee_running ? "yes" : "no");
        pthread_mutex_unlock(&ctx->state_mutex);
        free(trimmed);
        return true;
    }

    if (strcasecmp(command_name, "debugmode") == 0) {
        ctx->debug_mode = !ctx->debug_mode;
        printf("Debug mode: %s\n", ctx->debug_mode ? "enabled" : "disabled");
        // Also send to DAP thread to sync debug mode
        goto send_to_dap;
    }

send_to_dap:

    // Send DAP/connection commands to DAP client thread
    DAPUICommand* cmd = dap_ui_command_create(DAP_UI_CMD_EXECUTE, command_name, args);
    if (cmd) {
        cmd->command_id = dap_thread_context_get_next_id(ctx);
        int result = dap_command_queue_push(ctx->command_queue, cmd);
        if (result != 0) {
            printf("Error: Failed to send command to DAP thread\n");
            dap_ui_command_destroy(cmd);
        }
    } else {
        printf("Error: Failed to create command\n");
    }

    free(trimmed);
    return false; // DAP command, don't show prompt yet
}


static void handle_ui_events(DAPThreadContext* ctx) {
    if (!ctx) return;

    // Process all available events (non-blocking)
    DAPUIEvent* event;
    bool need_prompt_after_events = false;
    while ((event = dap_event_queue_pop(ctx->event_queue, 0)) != NULL) {
        switch (event->type) {
            case DAP_UI_EVENT_STOPPED:
                printf("\n🛑 %s\n", event->message);
                if (event->details && ctx->debug_mode) {
                    printf("Details: %s\n", event->details);
                }
                break;

            case DAP_UI_EVENT_CONTINUED:
                printf("\n▶️  %s\n", event->message);
                break;

            case DAP_UI_EVENT_TERMINATED:
                printf("\n🔚 %s\n", event->message);
                break;

            case DAP_UI_EVENT_OUTPUT:
                printf("\n📤 %s\n", event->message);
                break;

            case DAP_UI_EVENT_ERROR:
                printf("\n❌ Error: %s", event->message);
                if (event->error_code != 0) {
                    printf(" (code: %d)", event->error_code);
                }
                printf("\n");
                // Error received, we can show prompt now
                need_prompt_after_events = true;
                break;

            case DAP_UI_EVENT_STATUS_CHANGE:
                printf("\n🔗 %s\n", event->message);
                break;

            case DAP_UI_EVENT_BREAKPOINT:
                printf("\n🔴 %s\n", event->message);
                break;

            case DAP_UI_EVENT_RESPONSE:
                // For most responses, we don't need to show anything
                // unless it's an error or debug mode is on
                if (ctx->debug_mode && event->message) {
                    printf("\n✅ %s\n", event->message);
                }
                // Response received, we can show prompt now
                need_prompt_after_events = true;
                break;

            default:
                printf("\nUnknown event type: %d\n", event->type);
                break;
        }

        dap_ui_event_destroy(event);
    }

    // Show prompt after processing response events
    if (need_prompt_after_events) {
        printf(DAP_PROMPT);
        fflush(stdout);
    }
}

static void setup_terminal(void) {
    if (terminal_setup) return;

    // Save original terminal settings
    if (tcgetattr(STDIN_FILENO, &original_termios) == 0) {
        terminal_setup = true;

        if (isatty(STDIN_FILENO)) {
            // Set up terminal for raw input (character by character)
            struct termios raw = original_termios;
            raw.c_lflag &= ~(ECHO | ICANON);  // Disable echo and canonical mode
            raw.c_cc[VMIN] = 1;   // Read at least 1 character
            raw.c_cc[VTIME] = 0;  // No timeout
            tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        }

        // Enable history for command recall
        using_history();
    }
}

static void restore_terminal(void) {
    if (terminal_setup) {
        tcsetattr(STDIN_FILENO, TCSANOW, &original_termios);
        terminal_setup = false;
    }
}

static void print_prompt(void) {
    printf("(dap) ");
    fflush(stdout);
}