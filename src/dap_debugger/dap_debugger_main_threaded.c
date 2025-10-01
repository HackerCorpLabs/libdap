/**
 * @file dap_debugger_main_threaded.c
 * @brief Threaded main entry point for the Debug Adapter Protocol client
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include "dap_client.h"
#include "dap_debugger_threads.h"
#include "dap_debugger_files.h"
#include "dap_debugger_ui.h"

// Global variables
static DAPThreadContext* g_thread_ctx = NULL;

// Signal handler for graceful shutdown
static void signal_handler(int sig) {
    (void)sig;
    if (g_thread_ctx) {
        printf("\nShutdown requested...\n");
        dap_thread_context_request_shutdown(g_thread_ctx);

        // Give threads a moment to shutdown gracefully
        sleep(1);

        // Force exit if threads don't respond
        exit(0);
    }
}

// Function to send initial launch command once connected
static void send_launch_command(DAPThreadContext* ctx, const char* program_file) {
    if (!ctx || !program_file) return;

    // Create launch command
    char launch_args[1024];
    snprintf(launch_args, sizeof(launch_args), "%s", program_file);

    DAPUICommand* cmd = dap_ui_command_create(DAP_UI_CMD_EXECUTE, "launch", launch_args);
    if (cmd) {
        cmd->command_id = dap_thread_context_get_next_id(ctx);
        dap_command_queue_push(ctx->command_queue, cmd);
    }
}

int main(int argc, char* argv[]) {
    // Configuration
    char* host = NULL;
    int port = 4711;
    char* program_file = NULL;
    bool stop_on_entry = true;
    bool debug_mode = false;

    // Parse command line arguments
    static struct option long_options[] = {
        {"host", required_argument, 0, 'h'},
        {"port", required_argument, 0, 'p'},
        {"file", required_argument, 0, 'f'},
        {"no-stop-on-entry", no_argument, 0, 'E'},
        {"debug", no_argument, 0, 'd'},
        {"help", no_argument, 0, '?'},
        {0, 0, 0, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "h:p:f:Ed?", long_options, NULL)) != -1) {
        switch (c) {
            case 'h':
                free(host);
                host = strdup(optarg);
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'f':
                free(program_file);
                program_file = strdup(optarg);
                break;
            case 'E':
                stop_on_entry = false;
                break;
            case 'd':
                debug_mode = true;
                break;
            case '?':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Handle positional file argument
    if (optind < argc && !program_file) {
        program_file = strdup(argv[optind]);
    }

    // Discover files if program file is specified
    FileSet* file_set = NULL;
    if (program_file) {
        file_set = discover_files(program_file);
        if (!file_set) {
            fprintf(stderr, "Error: Failed to discover files for '%s'\n", program_file);
            free(host);
            free(program_file);
            return 1;
        }

        printf("File Discovery Results:\n");
        if (file_set->program_file) {
            printf("  Program file: %s\n", file_set->program_file);
        }
        if (file_set->source_file) {
            printf("  Source file:  %s\n", file_set->source_file);
        }
        if (file_set->map_file) {
            printf("  Map file:     %s\n", file_set->map_file);
        }
        printf("  Debug type:   %s\n",
               file_set->primary_type == FILE_TYPE_ASSEMBLY ? "Assembly" : "C");
        printf("\n");

        // Use the discovered program file
        free(program_file);
        program_file = strdup(file_set->program_file);
    }

    // Create thread context
    g_thread_ctx = dap_thread_context_create();
    if (!g_thread_ctx) {
        fprintf(stderr, "Error: Failed to create thread context\n");
        free(host);
        free(program_file);
        if (file_set) free_file_set(file_set);
        return 1;
    }

    // Configure context
    g_thread_ctx->host = host ? strdup(host) : strdup("localhost");
    g_thread_ctx->port = port;
    g_thread_ctx->program_file = program_file ? strdup(program_file) : NULL;
    g_thread_ctx->debug_mode = debug_mode;

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Starting DAP debugger (threaded version)\n");
    printf("Host: %s, Port: %d\n", g_thread_ctx->host, g_thread_ctx->port);
    if (g_thread_ctx->program_file) {
        printf("Program: %s\n", g_thread_ctx->program_file);
    }
    printf("\n");

    // Start DAP client thread
    if (pthread_create(&g_thread_ctx->dap_thread, NULL, dap_client_thread_main, g_thread_ctx) != 0) {
        fprintf(stderr, "Error: Failed to create DAP client thread\n");
        dap_thread_context_destroy(g_thread_ctx);
        free(host);
        free(program_file);
        if (file_set) free_file_set(file_set);
        return 1;
    }

    // Auto-connect if program file is specified
    if (g_thread_ctx->program_file) {
        printf("Auto-connecting to debug server...\n");

        // Send connect command
        DAPUICommand* connect_cmd = dap_ui_command_create(DAP_UI_CMD_CONNECT, NULL, NULL);
        if (connect_cmd) {
            connect_cmd->command_id = dap_thread_context_get_next_id(g_thread_ctx);
            dap_command_queue_push(g_thread_ctx->command_queue, connect_cmd);

            // Wait a bit for connection, then send launch
            sleep(1);
            send_launch_command(g_thread_ctx, g_thread_ctx->program_file);
        }
    }

    // Run UI in main thread instead of separate thread
    dap_ui_thread_main(g_thread_ctx);

    // UI exited, shutdown DAP thread
    dap_thread_context_request_shutdown(g_thread_ctx);
    pthread_join(g_thread_ctx->dap_thread, NULL);

    // Cleanup
    dap_thread_context_destroy(g_thread_ctx);
    free(host);
    free(program_file);
    if (file_set) free_file_set(file_set);

    printf("Debugger exited.\n");
    return 0;
}