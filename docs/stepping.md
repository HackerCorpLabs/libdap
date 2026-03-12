# Debugger Stepping and Events

## Introduction

This document describes how stepping and events work in the debugger, including the interaction between the Debug Adapter Protocol (DAP) client and server, and how various flags affect the debugging experience.

## Stepping Commands

The debugger supports several stepping commands:

1. **Step In** (`stepIn`): Steps into the current instruction/function
2. **Step Out** (`stepOut`): Steps out of the current function
3. **Step Over** (`next`): Steps over the current instruction/function
4. **Continue** (`continue`): Continues execution until the next breakpoint or pause
5. **Pause** (`pause`): Pauses execution at the current point

Each step command follows this pattern:
1. Client sends the step command
2. Server processes the command and updates its state
3. Server sends a `stopped` event with reason "step"
4. Client updates its UI to show the new location

## Examining Program State with Scopes

The debugger provides the `scopes` command to examine variables and program state at a specific stack frame. This is particularly useful when the program is stopped at a breakpoint or after a step command.

### Using the Scopes Command

To use the scopes command effectively:

1. **Set a breakpoint** in your code where you want to examine variables
2. **Run the program** until it hits the breakpoint
3. **Use the scopes command** to see variables in the current frame

You can also specify a frame ID directly to examine variables in a different frame of the stack trace.

### Scope Types

The debugger typically provides several types of scopes:

1. **CPU Registers**: Shows the current state of CPU registers
2. **CPU Flags**: Displays the status of CPU flags
3. **Internal Registers**: Shows internal debugger state

Each scope provides:
- A name identifying the scope
- A variables reference ID for accessing variables
- The number of named variables in the scope
- An "expensive" flag indicating if retrieving the scope is resource-intensive

### Example Usage

```bash
# Set a breakpoint
(dap) break 42

# Run the program
(dap) continue

# When stopped at breakpoint, examine scopes
(dap) scopes
Scopes for frame 1:
  CPU Registers (ref: 1, vars: 8)
  CPU Flags (ref: 1001, vars: 4)
  Internal Registers (ref: 4, vars: 2)

# Examine a specific frame's scopes
(dap) scopes 2
```

### Important Notes

- The scopes command only works when the program is stopped (at a breakpoint or after a step)
- Each scope's variables can be examined using the `variables` command with the scope's reference ID
- The "expensive" flag indicates that retrieving variables from that scope may be slow or resource-intensive
- Frame IDs can be obtained from the `stack` command

## Examining Variables

The debugger provides the `variables` command to examine the contents of a scope or variable container. This command is essential for inspecting program state, including CPU registers, memory contents, and program variables.

### Using the Variables Command

To use the variables command effectively:

1. **Get a variables reference** from:
   - A scope (using the `scopes` command)
   - A parent variable that has children
   - A memory location or register group

2. **Use the variables command** with the reference ID:
   ```bash
   # Basic usage with a reference ID
   (dap) variables 1
   
   # With filter for named variables only
   (dap) variables 1 named
   
   # With paging (start at index 0, get 10 variables)
   (dap) variables 1 named 0 10
   ```

### Variable Types and Properties

Variables in the debugger can have several properties:

1. **Name**: The identifier of the variable
2. **Value**: The current value of the variable
3. **Type**: The data type of the variable (if available)
4. **Variables Reference**: A reference ID if the variable has child variables
5. **Presentation Hint**: How the variable should be displayed (normal, readonly, hidden)

### Example Usage

```bash
# First, get scopes to find variable references
(dap) scopes
Scopes for frame 1:
  CPU Registers (ref: 1, vars: 8)
  CPU Flags (ref: 1001, vars: 4)
  Internal Registers (ref: 4, vars: 2)

# Examine CPU registers
(dap) variables 1
PC: 0x0000
SP: 0xFFFF
A:  0x0000
X:  0x0000
Y:  0x0000

# Examine CPU flags with named filter
(dap) variables 1001 named
C: 0 (Carry)
Z: 0 (Zero)
N: 0 (Negative)
V: 0 (Overflow)

# Examine a complex variable with children
(dap) variables 42
array[0] = 1 [has children, ref=43]
array[1] = 2 [has children, ref=44]
array[2] = 3 [has children, ref=45]
```

### Command Options

The variables command supports several options:

1. **Filter**:
   - `named`: Show only named variables
   - `indexed`: Show only indexed variables (e.g., array elements)

2. **Paging**:
   - `start`: Index of first variable to show
   - `count`: Maximum number of variables to show

### Important Notes

- Variables are only accessible when the program is stopped
- Some variables may be expensive to retrieve (indicated by the parent scope's "expensive" flag)
- Variables with children can be further examined using their reference ID
- The debugger maintains variable state even when the program is not running
- Memory and register variables are always accessible, regardless of program state

## Assembly-Level Debugging and CPU Registers

When debugging assembly code, the debugger provides direct access to CPU registers and memory, even before the program starts executing. This is different from high-level language debugging where scopes are typically tied to stack frames.

### Accessing CPU Registers

The debugger provides several ways to access CPU registers:

1. **Direct Register Access**:
   - Registers are always accessible, even before program execution starts
   - No need to wait for a breakpoint or stack frame
   - Registers are organized into logical groups (CPU Registers, CPU Flags, Internal Registers)

2. **Register Groups**:
   - **CPU Registers**: General-purpose and special-purpose registers (e.g., PC, SP, A, X, Y)
   - **CPU Flags**: Status and condition flags
   - **Internal Registers**: Debugger-specific registers and state

### Example Usage

```bash
# Access registers before program start
(dap) scopes
Scopes for frame 0:
  CPU Registers (ref: 1, vars: 8)
  CPU Flags (ref: 1001, vars: 4)
  Internal Registers (ref: 4, vars: 2)

# Examine CPU registers
(dap) variables 1
PC: 0x0000
SP: 0xFFFF
A:  0x0000
X:  0x0000
Y:  0x0000

# Examine CPU flags
(dap) variables 1001
C: 0 (Carry)
Z: 0 (Zero)
N: 0 (Negative)
V: 0 (Overflow)
```

### DAP Implementation Details

The debugger implements the following DAP features for assembly debugging:

1. **Register Access**:
   - Uses `readRegisters` and `writeRegisters` commands
   - Supports register groups and individual registers
   - Provides register values in appropriate formats (hex, octal, etc.)

2. **Memory Access**:
   - Uses `readMemory` and `writeMemory` commands
   - Supports memory inspection at any address
   - Handles memory alignment and permissions

3. **Disassembly**:
   - Uses `disassemble` command to view machine code
   - Supports symbol resolution
   - Maps instructions to source lines when available

### Important Notes

- Register access is always available, regardless of program state
- Memory access requires proper permissions and alignment
- Register values are displayed in the appropriate format for the architecture
- The debugger maintains register state even when the program is not running
- Some registers may be read-only or have special access requirements

## Events

The debugger sends several types of events:

### Stopped Event
Sent when execution stops, with different reasons:
- `entry`: When stopping at program entry (controlled by `stopOnEntry`)
- `step`: After a step command completes
- `breakpoint`: When hitting a breakpoint
- `pause`: When execution is manually paused
- `exception`: When an exception occurs

Example `stopped` event:
```json
{
    "reason": "step",
    "threadId": 1,
    "allThreadsStopped": true,
    "description": "Stepped into instruction",
    "text": "PC: 0x00000000",
    "source": {
        "path": "program.asm"
    },
    "line": 10,
    "column": 1
}
```

### Continued Event
Sent when execution continues:
```json
{
    "threadId": 1,
    "allThreadsContinued": true
}
```

## Flags and Their Impact

### stopOnEntry
- **Purpose**: Controls whether to stop at program entry
- **Default**: `false`
- **Behavior**:
  - When `true`: Debugger stops at first instruction and sends `stopped` event with reason "entry"
  - When `false`: Debugger starts running immediately
- **Usage**: Set via `-e` command line flag or in launch configuration
- **DAP Specification**: Required for initial register inspection before program execution begins

### noDebug
- **Purpose**: Controls whether to run without debugging
- **Default**: `false`
- **Behavior**:
  - When `true`: Program runs without debugger attached
  - When `false`: Normal debugging session
- **Usage**: Set in launch configuration

## Implementation Details

### Client-Side
The client maintains state about:
- Current thread
- Current source location
- Breakpoints
- Debugger state (running/paused)

### Server-Side
The server (mock implementation):
1. Updates program counter and line number on steps
2. Checks for breakpoints during execution
3. Sends appropriate events
4. Maintains debugger state

## DAP References

- [DAP Specification](https://microsoft.github.io/debug-adapter-protocol/specification)
- [Events Reference](https://microsoft.github.io/debug-adapter-protocol/specification#Events_Stopped)
- [Stepping Commands](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Next)
- [Launch Configuration](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Launch)

## Troubleshooting

Common issues and solutions:

1. **Step commands not working**
   - Check if debugger is paused
   - Verify thread ID is valid
   - Ensure program is loaded

2. **No events received**
   - Check server connection
   - Verify event handling is registered
   - Check for error responses

3. **stopOnEntry not working**
   - Verify flag is set correctly
   - Check launch configuration
   - Ensure server handles the flag

## Best Practices

1. Always wait for `stopped` event after step commands
2. Handle all possible event types
3. Update UI state based on events
4. Validate thread IDs and source locations
5. Implement proper error handling 