#include "dap_server.h"
#include <cjson/cJSON.h>

/**
 * @brief Enum for DAP server capability flags
 * Each enum value will be used as an index into the capabilities array
 */
typedef enum {
    // Supported capabilities (set to true)
    DAP_CAP_CONFIG_DONE_REQUEST,             // Supports configurationDone request to signal end of configuration sequence
    DAP_CAP_FUNCTION_BREAKPOINTS,            // Supports breakpoints on functions/methods by name
    DAP_CAP_CONDITIONAL_BREAKPOINTS,         // Supports breakpoints with conditional expressions
    DAP_CAP_HIT_CONDITIONAL_BREAKPOINTS,     // Supports breakpoints that break after N hits
    DAP_CAP_EVALUATE_FOR_HOVERS,             // Supports evaluate request in hover context (tooltips)
    DAP_CAP_SET_VARIABLE,                    // Supports changing variable values during debugging
    DAP_CAP_COMPLETIONS_REQUEST,             // Supports code completion within debug contexts
    DAP_CAP_MODULES_REQUEST,                 // Supports listing program modules/libraries
    DAP_CAP_RESTART_REQUEST,                 // Supports restarting debug session without terminating adapter
    DAP_CAP_EXCEPTION_OPTIONS,               // Supports custom exception handling configurations
    DAP_CAP_VALUE_FORMATTING_OPTIONS,        // Supports formatting options for variables/evaluation results
    DAP_CAP_EXCEPTION_INFO_REQUEST,          // Supports getting detailed exception information
    DAP_CAP_TERMINATE_DEBUGGEE,              // Supports terminating debuggee on disconnect
    DAP_CAP_DELAYED_STACK_TRACE_LOADING,     // Supports loading stack frames in chunks for performance
    DAP_CAP_LOADED_SOURCES_REQUEST,          // Supports listing all loaded source files
    DAP_CAP_LOG_POINTS,                      // Supports breakpoints that log messages without stopping
    DAP_CAP_TERMINATE_THREADS_REQUEST,       // Supports terminating specific threads
    DAP_CAP_SET_EXPRESSION,                  // Supports evaluating and assigning expressions
    DAP_CAP_TERMINATE_REQUEST,               // Supports graceful termination of debuggee
    DAP_CAP_DATA_BREAKPOINTS,                // Supports breakpoints triggered by data/memory changes
    DAP_CAP_READ_MEMORY_REQUEST,             // Supports reading from memory at specified location
    DAP_CAP_WRITE_MEMORY_REQUEST,            // Supports writing to memory at specified location
    DAP_CAP_DISASSEMBLE_REQUEST,             // Supports disassembling code at specified location
    DAP_CAP_CANCEL_REQUEST,                  // Supports cancellation of in-progress requests
    DAP_CAP_BREAKPOINT_LOCATIONS_REQUEST,    // Supports finding valid breakpoint locations in source
    DAP_CAP_STEPPING_GRANULARITY,            // Supports different stepping levels (statement/line/instruction)
    DAP_CAP_INSTRUCTION_BREAKPOINTS,         // Supports breakpoints on machine instructions
    DAP_CAP_EXCEPTION_FILTER_OPTIONS,        // Supports richer exception filter configuration
    DAP_CAP_SINGLE_THREAD_EXECUTION_REQUESTS,// Supports execution control of individual threads    
    DAP_CAP_STEP_BACK,                       // Supports backward stepping through program execution
    DAP_CAP_RESTART_FRAME,                   // Supports restarting execution from a specific stack frame
    DAP_CAP_GOTO_TARGETS_REQUEST,            // Supports jumping to arbitrary code locations
    DAP_CAP_STEP_IN_TARGETS_REQUEST,         // Supports stepping into specific functions when multiple options
    DAP_CAP_CLIPBOARD_CONTEXT,               // Supports evaluate request for clipboard content
    
    // Keep this last to get the total count of capabilities
    DAP_CAP_COUNT
} DAPCapabilityID;

/**
 * @brief Set a capability in the capability array
 * 
 * @param capability_id The capability enum value to set
 * @param supported Whether the capability is supported
 * @return int 0 on success, -1 if capability_id is out of range
 */
int dap_server_set_capability(DAPCapabilityID capability_id, bool supported);

/**
 * @brief Set multiple capabilities at once
 * 
 * This function accepts a variable number of capability ID and boolean pairs,
 * terminated by DAP_CAP_COUNT. For example:
 * 
 * dap_server_set_capabilities(server,
 *     DAP_CAP_CONFIG_DONE_REQUEST, true,
 *     DAP_CAP_FUNCTION_BREAKPOINTS, true,
 *     DAP_CAP_CONDITIONAL_BREAKPOINTS, true,
 *     DAP_CAP_COUNT  // Terminator
 * );
 * 
 * @param server The DAP server instance
 * @param ... Variable number of DAPCapabilityID and boolean pairs, terminated by DAP_CAP_COUNT
 * @return int The number of capabilities actually set
 */
int dap_server_set_capabilities(DAPServer *server, ...);

// Command handler declarations

int handle_disconnect(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_terminate(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_restart(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_set_breakpoints(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_source(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_threads(DAPServer* server,   cJSON* args, DAPResponse* response);
int handle_stack_trace(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_disassemble(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_break(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_scopes(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_variables(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_set_variable(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_evaluate(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_configuration_done(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_read_memory(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_write_memory(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_pause(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_set_exception_breakpoints(DAPServer *server, cJSON *args, DAPResponse *response);


// Callback function for handling DAP commands
int handle_launch(DAPServer* server, cJSON* args, DAPResponse* response) ;
int handle_attach(DAPServer* server, cJSON* args, DAPResponse* response);
int handle_initialize(DAPServer* server, cJSON* args, DAPResponse* response);


int handle_execution_control(DAPServer* server, DAPCommandType command, cJSON* args, DAPResponse* response);

/**
 * @brief Send the 'initialized' event to the client
 * This event should be sent after the successful response to an 'initialize' request
 * @param server Server instance
 * @return 0 on success, non-zero on failure
 */
int send_initialized_event(DAPServer *server);

int handle_continue(DAPServer *server, cJSON *args, DAPResponse *response);
int handle_next(DAPServer *server, cJSON *args, DAPResponse *response);
int handle_step_in(DAPServer *server, cJSON *args, DAPResponse *response);
int handle_step_out(DAPServer *server, cJSON *args, DAPResponse *response);

void cleanup_debugger_state(DAPServer *server);
void free_breakpoints_array(const DAPBreakpoint *breakpoints, int count);
void free_filter_arrays(const char **filter_ids, const char **filter_conditions, int count);
void free_variable_array(DAPVariable *variables, int count);
