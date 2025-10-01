#include "dap_debugger_threads.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <unistd.h>

// Command Queue Implementation
DAPCommandQueue* dap_command_queue_create(size_t capacity) {
    DAPCommandQueue* queue = calloc(1, sizeof(DAPCommandQueue));
    if (!queue) return NULL;

    queue->items = calloc(capacity, sizeof(DAPUICommand*));
    if (!queue->items) {
        free(queue);
        return NULL;
    }

    queue->capacity = capacity;
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    queue->shutdown = false;

    if (pthread_mutex_init(&queue->mutex, NULL) != 0 ||
        pthread_cond_init(&queue->not_empty, NULL) != 0 ||
        pthread_cond_init(&queue->not_full, NULL) != 0) {
        free(queue->items);
        free(queue);
        return NULL;
    }

    return queue;
}

void dap_command_queue_destroy(DAPCommandQueue* queue) {
    if (!queue) return;

    pthread_mutex_lock(&queue->mutex);

    // Free any remaining commands
    while (queue->count > 0) {
        DAPUICommand* cmd = queue->items[queue->head];
        queue->head = (queue->head + 1) % queue->capacity;
        queue->count--;
        dap_ui_command_destroy(cmd);
    }

    pthread_mutex_unlock(&queue->mutex);

    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
    free(queue->items);
    free(queue);
}

int dap_command_queue_push(DAPCommandQueue* queue, DAPUICommand* cmd) {
    if (!queue || !cmd) return -1;

    pthread_mutex_lock(&queue->mutex);

    if (queue->shutdown) {
        pthread_mutex_unlock(&queue->mutex);
        return -1;
    }

    // Wait for space
    while (queue->count >= queue->capacity && !queue->shutdown) {
        pthread_cond_wait(&queue->not_full, &queue->mutex);
    }

    if (queue->shutdown) {
        pthread_mutex_unlock(&queue->mutex);
        return -1;
    }

    queue->items[queue->tail] = cmd;
    queue->tail = (queue->tail + 1) % queue->capacity;
    queue->count++;

    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);

    return 0;
}

DAPUICommand* dap_command_queue_pop(DAPCommandQueue* queue, int timeout_ms) {
    if (!queue) return NULL;

    pthread_mutex_lock(&queue->mutex);

    struct timespec deadline;
    if (timeout_ms > 0) {
        struct timeval now;
        gettimeofday(&now, NULL);
        deadline.tv_sec = now.tv_sec + timeout_ms / 1000;
        deadline.tv_nsec = (now.tv_usec + (timeout_ms % 1000) * 1000) * 1000;
        if (deadline.tv_nsec >= 1000000000) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000;
        }
    }

    // Wait for data
    while (queue->count == 0 && !queue->shutdown) {
        int result;
        if (timeout_ms > 0) {
            result = pthread_cond_timedwait(&queue->not_empty, &queue->mutex, &deadline);
            if (result == ETIMEDOUT) {
                pthread_mutex_unlock(&queue->mutex);
                return NULL;
            }
        } else {
            pthread_cond_wait(&queue->not_empty, &queue->mutex);
        }
    }

    if (queue->count == 0) {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }

    DAPUICommand* cmd = queue->items[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;

    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);

    return cmd;
}

void dap_command_queue_shutdown(DAPCommandQueue* queue) {
    if (!queue) return;

    pthread_mutex_lock(&queue->mutex);
    queue->shutdown = true;
    pthread_cond_broadcast(&queue->not_empty);
    pthread_cond_broadcast(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
}

// Event Queue Implementation
DAPEventQueue* dap_event_queue_create(size_t capacity) {
    DAPEventQueue* queue = calloc(1, sizeof(DAPEventQueue));
    if (!queue) return NULL;

    queue->items = calloc(capacity, sizeof(DAPUIEvent*));
    if (!queue->items) {
        free(queue);
        return NULL;
    }

    queue->capacity = capacity;
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;

    if (pthread_mutex_init(&queue->mutex, NULL) != 0 ||
        pthread_cond_init(&queue->not_empty, NULL) != 0 ||
        pthread_cond_init(&queue->not_full, NULL) != 0) {
        free(queue->items);
        free(queue);
        return NULL;
    }

    return queue;
}

void dap_event_queue_destroy(DAPEventQueue* queue) {
    if (!queue) return;

    pthread_mutex_lock(&queue->mutex);

    // Free any remaining events
    while (queue->count > 0) {
        DAPUIEvent* event = queue->items[queue->head];
        queue->head = (queue->head + 1) % queue->capacity;
        queue->count--;
        dap_ui_event_destroy(event);
    }

    pthread_mutex_unlock(&queue->mutex);

    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
    free(queue->items);
    free(queue);
}

int dap_event_queue_push(DAPEventQueue* queue, DAPUIEvent* event) {
    if (!queue || !event) return -1;

    pthread_mutex_lock(&queue->mutex);

    // Wait for space (non-blocking for events - drop old events if needed)
    if (queue->count >= queue->capacity) {
        // Drop oldest event
        DAPUIEvent* old_event = queue->items[queue->head];
        queue->head = (queue->head + 1) % queue->capacity;
        queue->count--;
        dap_ui_event_destroy(old_event);
    }

    queue->items[queue->tail] = event;
    queue->tail = (queue->tail + 1) % queue->capacity;
    queue->count++;

    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);

    return 0;
}

DAPUIEvent* dap_event_queue_pop(DAPEventQueue* queue, int timeout_ms) {
    if (!queue) return NULL;

    pthread_mutex_lock(&queue->mutex);

    struct timespec deadline;
    if (timeout_ms > 0) {
        struct timeval now;
        gettimeofday(&now, NULL);
        deadline.tv_sec = now.tv_sec + timeout_ms / 1000;
        deadline.tv_nsec = (now.tv_usec + (timeout_ms % 1000) * 1000) * 1000;
        if (deadline.tv_nsec >= 1000000000) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000;
        }
    }

    // Wait for data
    while (queue->count == 0) {
        int result;
        if (timeout_ms > 0) {
            result = pthread_cond_timedwait(&queue->not_empty, &queue->mutex, &deadline);
            if (result == ETIMEDOUT) {
                pthread_mutex_unlock(&queue->mutex);
                return NULL;
            }
        } else if (timeout_ms == 0) {
            // Non-blocking mode - return immediately if no events
            pthread_mutex_unlock(&queue->mutex);
            return NULL;
        } else {
            // Negative timeout means wait indefinitely
            pthread_cond_wait(&queue->not_empty, &queue->mutex);
        }
    }

    DAPUIEvent* event = queue->items[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;

    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);

    return event;
}

// Command/Event creation and destruction
DAPUICommand* dap_ui_command_create(DAPUICommandType type, const char* command_name, const char* args) {
    DAPUICommand* cmd = calloc(1, sizeof(DAPUICommand));
    if (!cmd) return NULL;

    cmd->type = type;
    cmd->command_name = command_name ? strdup(command_name) : NULL;
    cmd->args = args ? strdup(args) : NULL;
    cmd->command_id = 0; // Will be set by caller
    cmd->user_data = NULL;

    return cmd;
}

void dap_ui_command_destroy(DAPUICommand* cmd) {
    if (!cmd) return;

    free(cmd->command_name);
    free(cmd->args);
    free(cmd);
}

DAPUIEvent* dap_ui_event_create(DAPUIEventType type, const char* message) {
    DAPUIEvent* event = calloc(1, sizeof(DAPUIEvent));
    if (!event) return NULL;

    event->type = type;
    event->message = message ? strdup(message) : NULL;
    event->details = NULL;
    event->command_id = 0;
    event->error_code = 0;
    event->data = NULL;

    return event;
}

void dap_ui_event_destroy(DAPUIEvent* event) {
    if (!event) return;

    free(event->message);
    free(event->details);
    free(event);
}

// Thread Context Implementation
DAPThreadContext* dap_thread_context_create(void) {
    DAPThreadContext* ctx = calloc(1, sizeof(DAPThreadContext));
    if (!ctx) return NULL;

    ctx->command_queue = dap_command_queue_create(64);
    ctx->event_queue = dap_event_queue_create(256);

    // Create eventfd for event notifications
    ctx->event_notify_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

    if (!ctx->command_queue || !ctx->event_queue || ctx->event_notify_fd < 0) {
        dap_command_queue_destroy(ctx->command_queue);
        dap_event_queue_destroy(ctx->event_queue);
        if (ctx->event_notify_fd >= 0) close(ctx->event_notify_fd);
        free(ctx);
        return NULL;
    }

    if (pthread_mutex_init(&ctx->state_mutex, NULL) != 0 ||
        pthread_mutex_init(&ctx->id_mutex, NULL) != 0) {
        dap_command_queue_destroy(ctx->command_queue);
        dap_event_queue_destroy(ctx->event_queue);
        free(ctx);
        return NULL;
    }

    ctx->connected = false;
    ctx->debuggee_running = false;
    ctx->shutdown_requested = false;
    ctx->next_command_id = 1;

    // Initialize cache values
    ctx->last_thread_id = 1;   // Default to thread 1
    ctx->last_frame_id = -1;   // Invalid until set by stackTrace
    ctx->last_variables_ref = 0; // Invalid until set by scopes

    return ctx;
}

void dap_thread_context_destroy(DAPThreadContext* ctx) {
    if (!ctx) return;

    dap_command_queue_destroy(ctx->command_queue);
    dap_event_queue_destroy(ctx->event_queue);

    pthread_mutex_destroy(&ctx->state_mutex);
    pthread_mutex_destroy(&ctx->id_mutex);

    if (ctx->event_notify_fd >= 0) {
        close(ctx->event_notify_fd);
    }

    free(ctx->host);
    free(ctx->program_file);
    free(ctx);
}

uint32_t dap_thread_context_get_next_id(DAPThreadContext* ctx) {
    if (!ctx) return 0;

    pthread_mutex_lock(&ctx->id_mutex);
    uint32_t id = ctx->next_command_id++;
    pthread_mutex_unlock(&ctx->id_mutex);

    return id;
}

bool dap_thread_context_is_connected(DAPThreadContext* ctx) {
    if (!ctx) return false;

    pthread_mutex_lock(&ctx->state_mutex);
    bool connected = ctx->connected;
    pthread_mutex_unlock(&ctx->state_mutex);

    return connected;
}

bool dap_thread_context_is_shutdown_requested(DAPThreadContext* ctx) {
    if (!ctx) return true;

    pthread_mutex_lock(&ctx->state_mutex);
    bool shutdown = ctx->shutdown_requested;
    pthread_mutex_unlock(&ctx->state_mutex);

    return shutdown;
}

void dap_thread_context_request_shutdown(DAPThreadContext* ctx) {
    if (!ctx) return;

    pthread_mutex_lock(&ctx->state_mutex);
    ctx->shutdown_requested = true;
    pthread_mutex_unlock(&ctx->state_mutex);

    // Signal command queue to shutdown
    dap_command_queue_shutdown(ctx->command_queue);
}

int dap_thread_context_push_event(DAPThreadContext* ctx, DAPUIEvent* event) {
    if (!ctx || !event) return -1;

    // Push event to queue
    int result = dap_event_queue_push(ctx->event_queue, event);

    // Signal main thread that an event is available
    if (result == 0 && ctx->event_notify_fd >= 0) {
        uint64_t value = 1;
        write(ctx->event_notify_fd, &value, sizeof(value));
    }

    return result;
}