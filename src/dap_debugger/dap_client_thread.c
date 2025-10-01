#include "dap_debugger_threads.h"
#include "dap_debugger_commands.h"
#include "dap_debugger_help.h"
#include "dap_response_formatter.h"
#include "dap_client.h"
#include "dap_protocol.h"
#include "dap_error.h"
#include "dap_transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <strings.h>
#include <cjson/cJSON.h>

// Forward declarations for internal functions
static void handle_dap_command(DAPThreadContext* ctx, DAPUICommand* cmd);
static void handle_dap_event(DAPThreadContext* ctx, cJSON* message);
static void handle_dap_response(DAPThreadContext* ctx, cJSON* message);
static void send_event_to_ui(DAPThreadContext* ctx, DAPUIEventType type, const char* message, uint32_t command_id);
static void send_error_to_ui(DAPThreadContext* ctx, const char* message, int error_code, uint32_t command_id);
static int send_dap_request_nonblocking(DAPThreadContext* ctx, const char* command_name, const char* args);
static void update_cache_from_response(DAPThreadContext* ctx, const char* command, cJSON* body);
static void format_and_send_response(DAPThreadContext* ctx, const char* command, cJSON* body, uint32_t command_id);

/**
 * Main DAP client thread function
 * Handles:
 * 1. DAP protocol communication (receives events/responses)
 * 2. Command execution from UI thread
 * 3. Event forwarding to UI thread
 */
void* dap_client_thread_main(void* arg) {
    DAPThreadContext* ctx = (DAPThreadContext*)arg;
    if (!ctx) {
        fprintf(stderr, "DAP thread: No context provided\n");
        return NULL;
    }

    send_event_to_ui(ctx, DAP_UI_EVENT_OUTPUT, "DAP client thread started", 0);

    // Main loop
    while (!dap_thread_context_is_shutdown_requested(ctx)) {
        fd_set read_fds;
        struct timeval timeout;
        int max_fd = -1;

        FD_ZERO(&read_fds);

        // Add DAP socket if connected
        if (ctx->client && ctx->client->connected) {
            FD_SET(ctx->client->fd, &read_fds);
            max_fd = ctx->client->fd;
        }

        // Set timeout for select (100ms to check for commands periodically)
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; // 100ms

        int ready = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (ready < 0) {
            if (errno == EINTR) {
                continue; // Interrupted by signal, continue
            }
            send_error_to_ui(ctx, "Select error in DAP thread", errno, 0);
            break;
        }

        // Check for DAP messages
        if (ready > 0 && ctx->client && ctx->client->connected && FD_ISSET(ctx->client->fd, &read_fds)) {
            cJSON* message = NULL;
            int recv_result = dap_client_receive_message(ctx->client, &message);

            if (recv_result == 0 && message) {
                const char* type = cJSON_GetStringValue(cJSON_GetObjectItem(message, "type"));

                if (type && strcmp(type, "event") == 0) {
                    handle_dap_event(ctx, message);
                } else if (type && strcmp(type, "response") == 0) {
                    handle_dap_response(ctx, message);
                }

                cJSON_Delete(message);
            } else if (recv_result == DAP_ERROR_TIMEOUT) {
                // Timeout is normal, continue
            } else {
                // Connection error
                if (ctx->client && !ctx->client->connected) {
                    send_event_to_ui(ctx, DAP_UI_EVENT_STATUS_CHANGE, "Disconnected from debug server", 0);

                    pthread_mutex_lock(&ctx->state_mutex);
                    ctx->connected = false;
                    pthread_mutex_unlock(&ctx->state_mutex);
                } else {
                    char error_msg[256];
                    snprintf(error_msg, sizeof(error_msg), "DAP receive error: %d (%s)",
                             recv_result, dap_error_message(recv_result));
                    send_error_to_ui(ctx, error_msg, recv_result, 0);
                }
            }
        }

        // Check for commands from UI (with short timeout)
        DAPUICommand* cmd = dap_command_queue_pop(ctx->command_queue, 100);
        if (cmd) {
            handle_dap_command(ctx, cmd);
            dap_ui_command_destroy(cmd);
        }
    }

    // Process any final commands before cleanup
    DAPUICommand* cmd;
    while ((cmd = dap_command_queue_pop(ctx->command_queue, 0)) != NULL) {
        handle_dap_command(ctx, cmd);
        dap_ui_command_destroy(cmd);
    }

    // Cleanup
    if (ctx->client) {
        if (ctx->client->connected) {
            DAPDisconnectResult result = {0};
            dap_client_disconnect(ctx->client, false, false, &result);
        }
        dap_client_free(ctx->client);
        ctx->client = NULL;
    }

    send_event_to_ui(ctx, DAP_UI_EVENT_OUTPUT, "DAP client thread exiting", 0);
    return NULL;
}

static void handle_dap_command(DAPThreadContext* ctx, DAPUICommand* cmd) {
    if (!ctx || !cmd) return;

    switch (cmd->type) {
        case DAP_UI_CMD_CONNECT: {
            if (ctx->client) {
                send_error_to_ui(ctx, "Already connected", 0, cmd->command_id);
                return;
            }

            // Create new client
            const char* host = ctx->host ? ctx->host : "localhost";
            int port = ctx->port > 0 ? ctx->port : 4711;

            ctx->client = dap_client_create(host, port);
            if (!ctx->client) {
                send_error_to_ui(ctx, "Failed to create DAP client", 0, cmd->command_id);
                return;
            }

            // Set reasonable timeout to prevent hanging (5 seconds)
            ctx->client->timeout_ms = 5000;

            // Connect to server
            int error = dap_client_connect(ctx->client);
            if (error != DAP_ERROR_NONE) {
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "Failed to connect to %s:%d (error %d)",
                         host, port, error);
                send_error_to_ui(ctx, error_msg, error, cmd->command_id);

                dap_client_free(ctx->client);
                ctx->client = NULL;
                return;
            }

            pthread_mutex_lock(&ctx->state_mutex);
            ctx->connected = true;
            pthread_mutex_unlock(&ctx->state_mutex);

            send_event_to_ui(ctx, DAP_UI_EVENT_STATUS_CHANGE, "Connected to debug server", cmd->command_id);
            break;
        }

        case DAP_UI_CMD_DISCONNECT: {
            if (!ctx->client || !ctx->client->connected) {
                send_error_to_ui(ctx, "Not connected", 0, cmd->command_id);
                return;
            }

            DAPDisconnectResult result = {0};
            dap_client_disconnect(ctx->client, false, false, &result);

            pthread_mutex_lock(&ctx->state_mutex);
            ctx->connected = false;
            ctx->debuggee_running = false;
            pthread_mutex_unlock(&ctx->state_mutex);

            send_event_to_ui(ctx, DAP_UI_EVENT_STATUS_CHANGE, "Disconnected from debug server", cmd->command_id);
            break;
        }

        case DAP_UI_CMD_EXECUTE: {

            // For DAP commands, check connection
            if (!ctx->client || !ctx->client->connected) {
                send_error_to_ui(ctx, "Not connected to debug server", 0, cmd->command_id);
                break;
            }

            // Find and execute the DAP command handler
            const DebuggerCommand* debug_cmd = find_command(cmd->command_name);
            if (!debug_cmd) {
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "Unknown command: %s", cmd->command_name);
                send_error_to_ui(ctx, error_msg, 0, cmd->command_id);
                break;
            }


            if (!debug_cmd->implemented) {
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "Command not implemented: %s", cmd->command_name);
                send_error_to_ui(ctx, error_msg, 0, cmd->command_id);
                break;
            }

            // Send DAP request without blocking (responses/events handled by main loop)
            // Use the canonical command name from the registry
            int result = send_dap_request_nonblocking(ctx, debug_cmd->name, cmd->args);

            if (result == 0) {
                // Request sent successfully
                if (ctx->debug_mode) {
                    send_event_to_ui(ctx, DAP_UI_EVENT_RESPONSE, "Request sent", cmd->command_id);
                }
            } else {
                // Failed to send request
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "Failed to send '%s' request",
                         cmd->command_name);
                send_error_to_ui(ctx, error_msg, result, cmd->command_id);
            }
            break;
        }

        case DAP_UI_CMD_SHUTDOWN: {
            dap_thread_context_request_shutdown(ctx);
            send_event_to_ui(ctx, DAP_UI_EVENT_RESPONSE, "Shutdown requested", cmd->command_id);
            break;
        }


        default:
            send_error_to_ui(ctx, "Unknown command type", 0, cmd->command_id);
            break;
    }
}

static void handle_dap_event(DAPThreadContext* ctx, cJSON* message) {
    if (!ctx || !message) return;

    const char* event = cJSON_GetStringValue(cJSON_GetObjectItem(message, "event"));
    if (!event) return;

    char* json_str = cJSON_Print(message);

    if (strcmp(event, "stopped") == 0) {
        const char* reason = NULL;
        cJSON* body = cJSON_GetObjectItem(message, "body");
        if (body) {
            reason = cJSON_GetStringValue(cJSON_GetObjectItem(body, "reason"));
        }

        pthread_mutex_lock(&ctx->state_mutex);
        ctx->debuggee_running = false;
        pthread_mutex_unlock(&ctx->state_mutex);

        char event_msg[256];
        snprintf(event_msg, sizeof(event_msg), "Stopped (reason: %s)", reason ? reason : "unknown");

        DAPUIEvent* ui_event = dap_ui_event_create(DAP_UI_EVENT_STOPPED, event_msg);
        if (ui_event) {
            ui_event->details = json_str; // Transfer ownership
            json_str = NULL;
            dap_thread_context_push_event(ctx, ui_event);
        }
    } else if (strcmp(event, "continued") == 0) {
        pthread_mutex_lock(&ctx->state_mutex);
        ctx->debuggee_running = true;
        pthread_mutex_unlock(&ctx->state_mutex);

        send_event_to_ui(ctx, DAP_UI_EVENT_CONTINUED, "Execution continued", 0);
    } else if (strcmp(event, "terminated") == 0) {
        pthread_mutex_lock(&ctx->state_mutex);
        ctx->debuggee_running = false;
        pthread_mutex_unlock(&ctx->state_mutex);

        send_event_to_ui(ctx, DAP_UI_EVENT_TERMINATED, "Debuggee terminated", 0);
    } else if (strcmp(event, "output") == 0) {
        cJSON* body = cJSON_GetObjectItem(message, "body");
        if (body) {
            const char* output = cJSON_GetStringValue(cJSON_GetObjectItem(body, "output"));
            if (output) {
                send_event_to_ui(ctx, DAP_UI_EVENT_OUTPUT, output, 0);
            }
        }
    } else {
        // Generic event
        char event_msg[256];
        snprintf(event_msg, sizeof(event_msg), "Event: %s", event);

        DAPUIEvent* ui_event = dap_ui_event_create(DAP_UI_EVENT_OUTPUT, event_msg);
        if (ui_event) {
            ui_event->details = json_str; // Transfer ownership
            json_str = NULL;
            dap_thread_context_push_event(ctx, ui_event);
        }
    }

    free(json_str);
}

static void handle_dap_response(DAPThreadContext* ctx, cJSON* message) {
    if (!ctx || !message) return;

    const char* command = cJSON_GetStringValue(cJSON_GetObjectItem(message, "command"));
    cJSON* success_obj = cJSON_GetObjectItem(message, "success");
    bool success = cJSON_IsTrue(success_obj);


    // Format and send beautiful response to UI
    if (command && success) {
        cJSON* body = cJSON_GetObjectItem(message, "body");
        if (body) {
            // Update cache from successful responses
            update_cache_from_response(ctx, command, body);
            format_and_send_response(ctx, command, body, 0);
        } else {
            char success_msg[256];
            snprintf(success_msg, sizeof(success_msg), "✅ %s completed successfully", command);
            send_event_to_ui(ctx, DAP_UI_EVENT_OUTPUT, success_msg, 0);
        }
    } else if (command && !success) {
        cJSON* message_obj = cJSON_GetObjectItem(message, "message");
        const char* error_msg = message_obj ? cJSON_GetStringValue(message_obj) : "Command failed";
        char formatted_error[512];
        snprintf(formatted_error, sizeof(formatted_error), "❌ %s failed: %s", command, error_msg);
        send_event_to_ui(ctx, DAP_UI_EVENT_ERROR, formatted_error, 0);
    }

    char response_msg[256];
    if (command) {
        snprintf(response_msg, sizeof(response_msg), "Response to %s: %s",
                 command, success ? "success" : "failed");
    } else {
        snprintf(response_msg, sizeof(response_msg), "Response: %s",
                 success ? "success" : "failed");
    }

    char* json_str = cJSON_Print(message);
    DAPUIEvent* ui_event = dap_ui_event_create(DAP_UI_EVENT_RESPONSE, response_msg);
    if (ui_event) {
        ui_event->details = json_str; // Transfer ownership
        dap_thread_context_push_event(ctx, ui_event);
    } else {
        free(json_str);
    }
}

static void send_event_to_ui(DAPThreadContext* ctx, DAPUIEventType type, const char* message, uint32_t command_id) {
    if (!ctx) return;

    DAPUIEvent* event = dap_ui_event_create(type, message);
    if (event) {
        event->command_id = command_id;
        dap_thread_context_push_event(ctx, event);
    }
}

static void send_error_to_ui(DAPThreadContext* ctx, const char* message, int error_code, uint32_t command_id) {
    if (!ctx) return;

    DAPUIEvent* event = dap_ui_event_create(DAP_UI_EVENT_ERROR, message);
    if (event) {
        event->error_code = error_code;
        event->command_id = command_id;
        dap_thread_context_push_event(ctx, event);
    }
}

static void update_cache_from_response(DAPThreadContext* ctx, const char* command, cJSON* body) {
    if (!ctx || !command || !body) return;

    pthread_mutex_lock(&ctx->state_mutex);

    // Update thread cache from threads response
    if (strcmp(command, "threads") == 0) {
        cJSON* threads_array = cJSON_GetObjectItem(body, "threads");
        if (cJSON_IsArray(threads_array)) {
            cJSON* first_thread = cJSON_GetArrayItem(threads_array, 0);
            if (first_thread) {
                cJSON* thread_id_obj = cJSON_GetObjectItem(first_thread, "id");
                if (cJSON_IsNumber(thread_id_obj)) {
                    ctx->last_thread_id = (int)cJSON_GetNumberValue(thread_id_obj);
                }
            }
        }
    }
    // Update frame cache from stackTrace response
    else if (strcmp(command, "stackTrace") == 0) {
        cJSON* frames_array = cJSON_GetObjectItem(body, "stackFrames");
        if (cJSON_IsArray(frames_array)) {
            cJSON* first_frame = cJSON_GetArrayItem(frames_array, 0);
            if (first_frame) {
                cJSON* frame_id_obj = cJSON_GetObjectItem(first_frame, "id");
                if (cJSON_IsNumber(frame_id_obj)) {
                    ctx->last_frame_id = (int)cJSON_GetNumberValue(frame_id_obj);
                }
            }
        }
    }
    // Update variables reference cache from scopes response
    else if (strcmp(command, "scopes") == 0) {
        cJSON* scopes_array = cJSON_GetObjectItem(body, "scopes");
        if (cJSON_IsArray(scopes_array)) {
            cJSON* first_scope = cJSON_GetArrayItem(scopes_array, 0);
            if (first_scope) {
                cJSON* var_ref_obj = cJSON_GetObjectItem(first_scope, "variablesReference");
                if (cJSON_IsNumber(var_ref_obj)) {
                    int var_ref = (int)cJSON_GetNumberValue(var_ref_obj);
                    if (var_ref > 0) {  // Only cache valid references
                        ctx->last_variables_ref = var_ref;
                    }
                }
            }
        }
    }

    pthread_mutex_unlock(&ctx->state_mutex);
}

static int send_dap_request_nonblocking(DAPThreadContext* ctx, const char* command_name, const char* args) {
    if (!ctx || !ctx->client || !command_name) return 1;

    if (!ctx->client->connected || !ctx->client->transport) {
        return 1;
    }

    // Create request object
    cJSON* request = cJSON_CreateObject();
    if (!request) return 1;

    // Add required fields
    cJSON_AddStringToObject(request, "type", "request");
    cJSON_AddNumberToObject(request, "seq", ctx->client->seq++);

    // Translate user commands to DAP commands
    const char* dap_command = command_name;
    if (strcmp(command_name, "step") == 0 || strcmp(command_name, "s") == 0) {
        dap_command = "stepIn";  // step into in DAP
    } else if (strcmp(command_name, "next") == 0 || strcmp(command_name, "n") == 0) {
        dap_command = "next";  // step over in DAP
    } else if (strcmp(command_name, "finish") == 0) {
        dap_command = "stepOut";  // step out in DAP
    }

    // Debug mode only
    if (ctx->debug_mode) {
        printf("Translating '%s' -> DAP command '%s'\n", command_name, dap_command);
    }

    cJSON_AddStringToObject(request, "command", dap_command);

    // Add arguments based on command type with validation and smart caching
    cJSON* arguments = cJSON_CreateObject();
    if (!arguments) {
        cJSON_Delete(request);
        return 1;
    }

    bool needs_arguments = false;
    bool validation_failed = false;
    char validation_error[256] = {0};

    // Handle different command types (use DAP command names)
    if (strcmp(dap_command, "launch") == 0) {
        if (!args || !*args) {
            strcpy(validation_error, "launch command requires a program path");
            validation_failed = true;
        } else {
            cJSON_AddStringToObject(arguments, "program", args);
            cJSON_AddBoolToObject(arguments, "stopOnEntry", true);
            cJSON_AddBoolToObject(arguments, "noDebug", false);
            needs_arguments = true;
        }
    } else if (strcmp(dap_command, "continue") == 0) {
        pthread_mutex_lock(&ctx->state_mutex);
        int thread_id = ctx->last_thread_id;
        pthread_mutex_unlock(&ctx->state_mutex);
        cJSON_AddNumberToObject(arguments, "threadId", thread_id);
        needs_arguments = true;
    } else if (strcmp(dap_command, "next") == 0 || strcmp(dap_command, "stepIn") == 0 || strcmp(dap_command, "stepOut") == 0) {
        pthread_mutex_lock(&ctx->state_mutex);
        int thread_id = ctx->last_thread_id;
        pthread_mutex_unlock(&ctx->state_mutex);
        cJSON_AddNumberToObject(arguments, "threadId", thread_id);
        needs_arguments = true;
    } else if (strcmp(dap_command, "pause") == 0) {
        pthread_mutex_lock(&ctx->state_mutex);
        int thread_id = ctx->last_thread_id;
        pthread_mutex_unlock(&ctx->state_mutex);
        cJSON_AddNumberToObject(arguments, "threadId", thread_id);
        needs_arguments = true;
    } else if (strcmp(dap_command, "stackTrace") == 0) {
        int thread_id;
        bool used_cache = false;

        if (args && *args) {
            thread_id = atoi(args);
            if (thread_id <= 0) {
                pthread_mutex_lock(&ctx->state_mutex);
                thread_id = ctx->last_thread_id;
                used_cache = true;
                pthread_mutex_unlock(&ctx->state_mutex);
            }
        } else {
            pthread_mutex_lock(&ctx->state_mutex);
            thread_id = ctx->last_thread_id;
            used_cache = true;
            pthread_mutex_unlock(&ctx->state_mutex);
        }

        cJSON_AddNumberToObject(arguments, "threadId", thread_id);
        needs_arguments = true;

        if (used_cache && ctx->debug_mode) {
            printf("Using cached thread ID: %d\n", thread_id);
        }

        // Update cache
        pthread_mutex_lock(&ctx->state_mutex);
        ctx->last_thread_id = thread_id;
        pthread_mutex_unlock(&ctx->state_mutex);

    } else if (strcmp(dap_command, "scopes") == 0) {
        int frame_id;
        bool used_cache = false;

        if (args && *args) {
            frame_id = atoi(args);
        } else {
            pthread_mutex_lock(&ctx->state_mutex);
            frame_id = ctx->last_frame_id;
            used_cache = true;
            pthread_mutex_unlock(&ctx->state_mutex);

            if (frame_id < 0) {
                strcpy(validation_error, "scopes command requires a frame ID (get from stackTrace)");
                validation_failed = true;
            }
        }

        if (!validation_failed) {
            cJSON_AddNumberToObject(arguments, "frameId", frame_id);
            needs_arguments = true;

            if (used_cache && ctx->debug_mode) {
                printf("Using cached frame ID: %d\n", frame_id);
            }

            // Update cache
            pthread_mutex_lock(&ctx->state_mutex);
            ctx->last_frame_id = frame_id;
            pthread_mutex_unlock(&ctx->state_mutex);
        }

    } else if (strcmp(dap_command, "variables") == 0) {
        int var_ref;
        bool used_cache = false;

        if (args && *args) {
            var_ref = atoi(args);
            if (var_ref <= 0) {
                strcpy(validation_error, "variables command requires a valid variables reference > 0 (get from scopes)");
                validation_failed = true;
            }
        } else {
            pthread_mutex_lock(&ctx->state_mutex);
            var_ref = ctx->last_variables_ref;
            used_cache = true;
            pthread_mutex_unlock(&ctx->state_mutex);

            if (var_ref <= 0) {
                strcpy(validation_error, "variables command requires a variables reference (get from scopes)");
                validation_failed = true;
            }
        }

        if (!validation_failed) {
            cJSON_AddNumberToObject(arguments, "variablesReference", var_ref);
            needs_arguments = true;

            if (used_cache && ctx->debug_mode) {
                printf("Using cached variables reference: %d\n", var_ref);
            }

            // Update cache
            pthread_mutex_lock(&ctx->state_mutex);
            ctx->last_variables_ref = var_ref;
            pthread_mutex_unlock(&ctx->state_mutex);
        }

    } else if (strcmp(dap_command, "readMemory") == 0) {
        if (!args || !*args) {
            strcpy(validation_error, "readMemory command requires a memory reference (address or symbol)");
            validation_failed = true;
        } else {
            // Parse arguments: memory_reference [count] [offset]
            char* args_copy = strdup(args);
            if (args_copy) {
                char* memory_ref = strtok(args_copy, " ");
                char* count_str = strtok(NULL, " ");
                char* offset_str = strtok(NULL, " ");

                if (memory_ref) {
                    cJSON_AddStringToObject(arguments, "memoryReference", memory_ref);

                    int count = count_str ? atoi(count_str) : 16;
                    int offset = offset_str ? atoi(offset_str) : 0;

                    if (count <= 0 || count > 1024) {
                        count = 16; // Default to 16 bytes
                    }
                    if (offset < 0) {
                        offset = 0; // Default to 0 offset
                    }

                    cJSON_AddNumberToObject(arguments, "count", count);
                    cJSON_AddNumberToObject(arguments, "offset", offset);
                    needs_arguments = true;
                } else {
                    strcpy(validation_error, "readMemory command requires a valid memory reference");
                    validation_failed = true;
                }
                free(args_copy);
            } else {
                strcpy(validation_error, "readMemory command: memory allocation failed");
                validation_failed = true;
            }
        }
    }

    // Handle validation failure
    if (validation_failed) {
        cJSON_Delete(arguments);
        cJSON_Delete(request);

        // Send error to UI
        send_error_to_ui(ctx, validation_error, 1, 0);
        return 1;
    }

    // Add arguments if needed
    if (needs_arguments) {
        cJSON_AddItemToObject(request, "arguments", arguments);
    } else {
        cJSON_Delete(arguments);
    }

    // Serialize and send
    char* message_str = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);
    if (!message_str) return 1;

    int result = dap_transport_send(ctx->client->transport, message_str);
    free(message_str);

    return (result == 0) ? 0 : 1;
}

static void format_and_send_response(DAPThreadContext* ctx, const char* command, cJSON* body, uint32_t command_id) {
    if (!ctx || !command || !body) return;

    // Use the reusable table formatter
    TableFormatter* formatter = table_formatter_create();
    if (!formatter) return;

    bool success = format_dap_response(formatter, command, body);
    if (success) {
        const char* formatted_output = table_formatter_get_output(formatter);
        if (formatted_output && strlen(formatted_output) > 0) {
            send_event_to_ui(ctx, DAP_UI_EVENT_OUTPUT, formatted_output, command_id);
        }
    }

    table_formatter_destroy(formatter);
}