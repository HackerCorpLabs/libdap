/**
 * @file dbg_mock_main.c
 * @brief Main entry point for the mock Debug Adapter Protocol server
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include "dap_mock_server.h"
#include "../libdap/include/dap_server.h"

// Declare the mock debugger state
extern MockDebugger mock_debugger;

#define DEFAULT_PORT 4711

/**
 * Signal handler for graceful shutdown
 */
static void handle_signal(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\nReceived signal %d, shutting down...\n", sig);
        dbg_mock_cleanup();
        exit(EXIT_SUCCESS);
    }
}

/**
 * Print usage information
 */
static void print_usage(const char* program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -p PORT     Specify the port to listen on (default: %d)\n", DEFAULT_PORT);
    printf("  -d, --debug Enable debug logging\n");
    printf("  -h          Display this help message and exit\n");
}

/**
 * Main entry point
 */
int main(int argc, char* argv[]) {
    // Parse command line arguments
    int port = DEFAULT_PORT;
    bool debug_mode = false;
    
    // Define long options
    static struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"debug", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "p:dh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                if (port <= 0 || port > 65535) {
                    fprintf(stderr, "Error: Invalid port number. Must be between 1 and 65535.\n");
                    return EXIT_FAILURE;
                }
                break;
            case 'd':
                debug_mode = true;
                printf("Debug mode enabled\n");
                break;
            case 'h':
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }
    
    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Initialize the mock debugger
    if (dbg_mock_init(port) != 0) {
        fprintf(stderr, "Error: Failed to initialize mock debugger.\n");
        return EXIT_FAILURE;
    }
    
    // Enable debug logging if requested
    if (debug_mode) {
        printf("Enabling transport debug logging\n");
        mock_debugger.server->transport->debuglog = true;
    }
    
    // Start the mock debugger
    if (dbg_mock_start() != 0) {
        fprintf(stderr, "Error: Failed to start mock debugger.\n");
        dbg_mock_cleanup();
        return EXIT_FAILURE;
    }
    
    printf("Mock debugger listening on port %d...\n", port);
    printf("Press Ctrl+C to exit\n");
    
    // Run the server's message processing loop
    if (dap_server_run(mock_debugger.server) != 0) {
        fprintf(stderr, "Error: Server message loop failed.\n");
        dbg_mock_cleanup();
        return EXIT_FAILURE;
    }
    
    // This point is never reached due to signal handler,
    // but cleanup is good practice
    dbg_mock_cleanup();
    return EXIT_SUCCESS;
} 