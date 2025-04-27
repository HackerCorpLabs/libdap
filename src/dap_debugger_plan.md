# DAP Client Main Refactoring Plan

## 0. Library Completion Prerequisite
- **Before refactoring the main client shell, ensure all required DAP client API functions are implemented in the library (`libdap/src/dap_debugger.c`).**
- The following functions are declared in the header but not implemented and must be created (even as stubs):
  - `dap_debugger_step`
  - `dap_debugger_get_threads`
  - `dap_debugger_pause`
  - `dap_debugger_continue`
  - `dap_debugger_get_stack_trace`
  - `dap_debugger_initialize`
  - `dap_debugger_launch`
  - `dap_debugger_receive_message`
- Each function should match its declaration in `dap_debugger.h` and return a suitable error code or stub value if not yet implemented.
- This ensures the shell can link and compile against the public API, and allows incremental development and testing.

---

## 1. General Refactoring Principles
- Do not change the library (`libdap`); only refactor `src/dap_debugger_main.c`.
- Use only the public, standardized API from the DAP client library.
- All DAP commands and events should be accessible via the shell.
- All function calls must match the signatures and error handling conventions of the library.
- The shell should be robust, user-friendly, and extensible.

---

## 2. Command Handling Architecture
- Implement a **command dispatch table** mapping shell commands to handler functions.
- Each handler function should:
  - Parse arguments from the shell.
  - Build the appropriate request using the DAP client API.
  - Print results or errors in a user-friendly way.
- Add a generic handler for unknown or unsupported commands.

---

## 3. Supported DAP Requests (Commands)
For each DAP request, implement a shell command and handler:
- **Session/Program Control**
  - `initialize`
  - `launch`
  - `attach`
  - `disconnect`
  - `terminate`
  - `restart`
- **Execution Control**
  - `continue`
  - `pause`
  - `next` (step over)
  - `stepIn`
  - `stepOut`
  - `stepBack`
- **Breakpoints**
  - `setBreakpoints`
  - `setFunctionBreakpoints`
  - `setInstructionBreakpoints`
  - `setExceptionBreakpoints`
- **Threads/Stack**
  - `threads`
  - `stackTrace`
  - `scopes`
  - `variables`
- **Source/Modules**
  - `source`
  - `loadedSources`
  - `modules`
  - `loadSources`
- **Memory/Registers**
  - `readMemory`
  - `writeMemory`
  - `readRegisters`
  - `writeRegisters`
- **Evaluation**
  - `evaluate`
  - `setVariable`
  - `setExpression`
- **Disassembly**
  - `disassemble`
- **Other**
  - `runInTerminal`
  - `custom` (for custom/experimental requests)

---

## 4. Supported DAP Events
- Implement an **event loop** that listens for and prints all DAP events, including:
  - `stopped`
  - `continued`
  - `terminated`
  - `exited`
  - `output`
  - `breakpoint`
  - `thread`
  - `loadedSource`
  - `process`
  - `module`
  - `initialized`
  - `capabilities`
  - `runInTerminal`
  - Any custom/experimental events

---

## 5. Shell Features
- **Command completion** and **history** (already present, keep/improve).
- **Help system**: `help` command for listing and describing all supported commands.
- **Error handling**: Print clear error messages for failed requests or invalid input.
- **Session state**: Track and display connection status, program state, etc.

---

## 6. Non-blocking Input and Event Loop Design
- The shell reads input character by character in a non-blocking mode (no readline).
- The main loop should:
  1. Check for new command (CR/LF).
  2. If not CR/LF, handle character input (insert, delete, arrow navigation, tab completion, etc.).
  3. If no keyboard input, check if any DAP event or response has been received and handle it.
- Received events can be printed immediately, but the design should allow for queuing/buffering events for future UI modes.
- This architecture enables responsive user input and real-time event handling, and is extensible for future UI enhancements (e.g., event panes, status bars).

---

## 7. Debugging and Raw JSON Output
- Add a debug macro (e.g., `#define DAP_DEBUG_PRINT_JSON`) to control raw JSON output.
- When enabled, all received DAP events and responses are printed as raw JSON for debugging, in addition to pretty-printed user output.
- This macro can be toggled for development or production use.
- Pretty print should always be used for user-facing output, but raw JSON is invaluable for debugging and protocol inspection.

---

## 8. Refactoring Steps
1. **Remove all legacy/implicit/duplicate DAP function calls** (e.g., `dap_debugger_threads`, `dap_debugger_stack_trace`).
2. **Replace with standardized API calls** (e.g., `dap_debugger_get_threads`, `dap_debugger_get_stack_trace`).
3. **Update all type names** to match the library (e.g., `DAPGetThreadsResult`).
4. **Update all function calls** to use the correct number and type of arguments.
5. **Add missing macro definitions** for DAP event/command names if not included from the library.
6. **Implement a main event loop** that:
   - Waits for and processes DAP events.
   - Dispatches shell commands to handlers.
7. **For each DAP command**, implement a handler that:
   - Parses shell input.
   - Calls the correct library function.
   - Prints the result or error.
8. **For each DAP event**, implement a handler that:
   - Prints event details in a user-friendly way.
   - Optionally updates session state.
9. **Test**: Ensure every DAP command and event can be exercised from the shell.

---

## 9. Extensibility
- Make it easy to add new DAP commands/events in the future.
- Use tables/structs for command and event registration.

---

## 10. Documentation
- Document all shell commands and their arguments.
- Provide usage examples for each command.
- Document the event loop and how events are displayed.

---

## 11. Testing
- Add a test mode or script to exercise all DAP commands and events.
- Ensure robust error handling for all edge cases.

---

**Next Steps:**
- Refactor `src/dap_debugger_main.c` according to this plan.
- Implement or stub out handlers for all DAP commands and events.
- Ensure the shell is fully spec-compliant and user-friendly.
