#ifndef DAP_DEBUGGER_THREADS_H
#define DAP_DEBUGGER_THREADS_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include "dap_client.h"
#include "dap_debugger_types.h"

// Forward declarations
typedef struct DAPUICommand DAPUICommand;
typedef struct DAPUIEvent DAPUIEvent;
typedef struct DAPThreadContext DAPThreadContext;

// Command types from UI to DAP thread
typedef enum {
    DAP_UI_CMD_EXECUTE = 1,     // Execute a debugger command
    DAP_UI_CMD_SHUTDOWN,        // Shutdown DAP thread
    DAP_UI_CMD_CONNECT,         // Connect to debug server
    DAP_UI_CMD_DISCONNECT,      // Disconnect from debug server
    DAP_UI_CMD_GET_STATUS       // Get current status
} DAPUICommandType;

// Event types from DAP thread to UI
typedef enum {
    DAP_UI_EVENT_STOPPED = 1,   // Debuggee stopped
    DAP_UI_EVENT_CONTINUED,     // Debuggee continued
    DAP_UI_EVENT_TERMINATED,    // Debuggee terminated
    DAP_UI_EVENT_OUTPUT,        // Output message
    DAP_UI_EVENT_ERROR,         // Error message
    DAP_UI_EVENT_STATUS_CHANGE, // Connection status changed
    DAP_UI_EVENT_BREAKPOINT,    // Breakpoint event
    DAP_UI_EVENT_RESPONSE       // Response to a command
} DAPUIEventType;

// Command structure sent from UI to DAP thread
struct DAPUICommand {
    DAPUICommandType type;
    char* command_name;         // Command name (e.g., "continue", "step")
    char* args;                 // Command arguments
    uint32_t command_id;        // Unique ID for matching responses
    void* user_data;            // Optional user data
};

// Event structure sent from DAP thread to UI
struct DAPUIEvent {
    DAPUIEventType type;
    char* message;              // Event message/output
    char* details;              // Additional details (JSON, etc.)
    uint32_t command_id;        // Associated command ID (for responses)
    int error_code;             // Error code (for errors)
    void* data;                 // Optional event-specific data
};

// Thread-safe queue for commands
typedef struct {
    DAPUICommand** items;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    bool shutdown;
} DAPCommandQueue;

// Thread-safe queue for events
typedef struct {
    DAPUIEvent** items;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} DAPEventQueue;

// Main thread context
struct DAPThreadContext {
    // Thread handles
    pthread_t dap_thread;

    // Communication queues
    DAPCommandQueue* command_queue;
    DAPEventQueue* event_queue;

    // Event notification file descriptor
    int event_notify_fd;  // eventfd to signal main thread when events arrive

    // DAP client (owned by DAP thread)
    DAPClient* client;

    // Shared state (protected by mutex)
    pthread_mutex_t state_mutex;
    bool connected;
    bool debuggee_running;
    bool shutdown_requested;

    // Configuration
    char* host;
    int port;
    char* program_file;
    bool debug_mode;

    // Command ID counter
    pthread_mutex_t id_mutex;
    uint32_t next_command_id;

    // Smart parameter cache (protected by state_mutex)
    int last_thread_id;
    int last_frame_id;
    int last_variables_ref;
};

// Function declarations
DAPThreadContext* dap_thread_context_create(void);
void dap_thread_context_destroy(DAPThreadContext* ctx);

// Queue operations
DAPCommandQueue* dap_command_queue_create(size_t capacity);
void dap_command_queue_destroy(DAPCommandQueue* queue);
int dap_command_queue_push(DAPCommandQueue* queue, DAPUICommand* cmd);
DAPUICommand* dap_command_queue_pop(DAPCommandQueue* queue, int timeout_ms);
void dap_command_queue_shutdown(DAPCommandQueue* queue);

DAPEventQueue* dap_event_queue_create(size_t capacity);
void dap_event_queue_destroy(DAPEventQueue* queue);
int dap_event_queue_push(DAPEventQueue* queue, DAPUIEvent* event);
DAPUIEvent* dap_event_queue_pop(DAPEventQueue* queue, int timeout_ms);

// Context-aware event push (signals main thread)
int dap_thread_context_push_event(DAPThreadContext* ctx, DAPUIEvent* event);

// Command/Event creation and destruction
DAPUICommand* dap_ui_command_create(DAPUICommandType type, const char* command_name, const char* args);
void dap_ui_command_destroy(DAPUICommand* cmd);

DAPUIEvent* dap_ui_event_create(DAPUIEventType type, const char* message);
void dap_ui_event_destroy(DAPUIEvent* event);

// Thread functions
void* dap_client_thread_main(void* arg);
void* dap_ui_thread_main(void* arg);

// Utility functions
uint32_t dap_thread_context_get_next_id(DAPThreadContext* ctx);
bool dap_thread_context_is_connected(DAPThreadContext* ctx);
bool dap_thread_context_is_shutdown_requested(DAPThreadContext* ctx);
void dap_thread_context_request_shutdown(DAPThreadContext* ctx);

#endif // DAP_DEBUGGER_THREADS_H