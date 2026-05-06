# DAP Debugger Command Reference

This document provides a comprehensive reference for all commands available in the libDAP debugger client, including the advanced threaded version (`dap_debugger_threaded`).

## 🎯 Quick Start

```bash
# Start the advanced threaded debugger
./build/bin/dap_debugger_threaded

# Basic workflow
dap# help                    # Show all commands
dap# srv                     # Check server capabilities
dap# launch program.exe      # Start debugging
dap# threads                 # List threads
dap# stackTrace              # Show call stack
dap# x 0x401000             # Examine memory
dap# continue                # Resume execution
```

## 📋 Command Categories

### 🎮 Execution Control

Commands for controlling program execution flow.

#### `continue` (aliases: `c`, `cont`)
**Purpose**: Resume execution of the debugged program.
**Syntax**: `continue [thread_id]`
**Examples**:
```bash
dap# continue              # Continue all threads
dap# c 1                   # Continue specific thread
```

#### `next` (aliases: `n`, `over`)
**Purpose**: Execute the next line of code, stepping over function calls.
**Syntax**: `next [thread_id]`
**Examples**:
```bash
dap# next                  # Step over in current thread
dap# n 1                   # Step over in thread 1
```

#### `stepIn` (aliases: `s`, `step`)
**Purpose**: Step into function calls.
**Syntax**: `stepIn [thread_id]`
**Examples**:
```bash
dap# step                  # Step into in current thread
dap# s 1                   # Step into in thread 1
```

#### `stepOut` (aliases: `o`, `step-out`)
**Purpose**: Step out of the current function.
**Syntax**: `stepOut [thread_id]`
**Examples**:
```bash
dap# stepOut               # Step out in current thread
dap# o 1                   # Step out in thread 1
```

#### `pause` (aliases: `p`)
**Purpose**: Pause execution of the debugged program.
**Syntax**: `pause [thread_id]`
**Examples**:
```bash
dap# pause                 # Pause all threads
dap# p 1                   # Pause specific thread
```

### 🚀 Program Control

Commands for managing the debug session and target program.

#### `launch` (aliases: `r`, `run`)
**Purpose**: Launch a new debug session.
**Syntax**: `launch [program_file]`
**Examples**:
```bash
dap# launch program.exe    # Launch specific program
dap# run                   # Launch current program
```

#### `attach`
**Purpose**: Attach to a running process.
**Syntax**: `attach <process_id>`
**Examples**:
```bash
dap# attach 1234           # Attach to process ID 1234
```

#### `restart`
**Purpose**: Restart the current debug session.
**Syntax**: `restart`
**Examples**:
```bash
dap# restart               # Restart current session
```

#### `disconnect`
**Purpose**: Disconnect from the debug server.
**Syntax**: `disconnect`
**Examples**:
```bash
dap# disconnect            # Clean disconnect
```

#### `terminate`
**Purpose**: Terminate the debugged program.
**Syntax**: `terminate`
**Examples**:
```bash
dap# terminate             # Stop the program
```

### 🔴 Breakpoints

Commands for managing breakpoints and debugging stops.

#### `setBreakpoints` (aliases: `b`, `break`)
**Purpose**: Set line breakpoints in source code.
**Syntax**: `setBreakpoints <file> <line> [condition]`
**Examples**:
```bash
dap# break main.c 42       # Set breakpoint at line 42
dap# b main.c 42 x > 10    # Conditional breakpoint
```

#### `setExceptionBreakpoints` (aliases: `ex`, `exception`)
**Purpose**: Set breakpoints on exceptions.
**Syntax**: `setExceptionBreakpoints <exception_type>`
**Examples**:
```bash
dap# exception all         # Break on all exceptions
dap# ex user               # Break on user exceptions
```

### 🔍 Information & Inspection

Commands for examining program state and data.

#### `threads` (aliases: `t`)
**Purpose**: List all threads in the debugged program.
**Syntax**: `threads`
**Examples**:
```bash
dap# threads               # Show all threads
dap# t                     # Short alias
```
**Output**: Beautiful Unicode table showing thread ID, name, and state.

#### `stackTrace` (aliases: `bt`, `backtrace`)
**Purpose**: Show the call stack for the current or specified thread.
**Syntax**: `stackTrace [thread_id]`
**Examples**:
```bash
dap# stackTrace            # Stack for current thread
dap# bt 1                  # Stack for thread 1
```
**Features**: Smart caching - remembers thread ID for subsequent commands.

#### `scopes` (aliases: `s`)
**Purpose**: Show variable scopes for the current stack frame.
**Syntax**: `scopes [frame_id]`
**Examples**:
```bash
dap# scopes                # Scopes for current frame
dap# scopes 0              # Scopes for frame 0
```
**Features**: Smart caching - uses frame ID from stackTrace automatically.

#### `variables` (aliases: `v`, `vars`)
**Purpose**: Show variables with hierarchical display and type information.
**Syntax**: `variables [variables_reference]`
**Examples**:
```bash
dap# variables             # Uses cached reference from scopes
dap# vars 1001             # Show variables for reference 1001
```
**Features**: Smart caching - uses variables reference from scopes automatically.

#### `evaluate` (aliases: `e`, `eval`)
**Purpose**: Evaluate expressions in the current context.
**Syntax**: `evaluate <expression>`
**Examples**:
```bash
dap# evaluate x + y        # Simple expression
dap# eval myvar->field     # Complex expression
```

#### `source` (aliases: `l`, `list`)
**Purpose**: Get source code content.
**Syntax**: `source <file> [start_line] [end_line]`
**Examples**:
```bash
dap# source main.c         # Show entire file
dap# list main.c 10 20     # Show lines 10-20
```

### 🧠 Memory & Assembly

Advanced commands for low-level debugging and memory examination.

#### `readMemory` (aliases: `x`, `memory`)
**Purpose**: Professional hex dump of memory with base64 decoding.
**Syntax**: `readMemory <memory_reference> [count] [offset]`
**Examples**:
```bash
dap# x 0x401000            # Read 16 bytes at address
dap# memory 0x401000 64    # Read 64 bytes
dap# readMemory main 32 8  # Read 32 bytes at main+8
```
**Output**: Industry-standard hex dump format with ASCII representation.

##### Address encoding (libdap extension)

The `memoryReference` argument for `readMemory`, `writeMemory`, and
`disassemble` supports the format: `[prefix:]address[@pil]`

**Address-space prefix** (optional, default=virtual):

| Prefix     | Meaning                                              |
|------------|------------------------------------------------------|
| *(none)*   | Virtual address (default)                            |
| `virt:`    | Virtual address                                      |
| `V:`       | Virtual address (short form)                         |
| `phys:`    | Physical address (bypass MMU)                        |
| `P:`       | Physical address (short form)                        |
| `ispace:`  | I-space (instruction page table, PT field of PCR)    |
| `I:`       | I-space (short form)                                 |
| `dspace:`  | D-space (data page table, APT field of PCR)          |
| `D:`       | D-space (short form)                                 |

**@PIL suffix** (optional, default=current PIL):

Append `@N` (N=0-15) to use a specific PIL's page table for address
translation. This lets you inspect memory as seen by a different
interrupt level -- e.g., read user process memory (PIL 1) while stopped
in the kernel (PIL 0 or 14). Physical addresses ignore @PIL since they
bypass the MMU.

Examples:
```bash
dap# readMemory 0x10000           # virtual, current PIL
dap# readMemory phys:0x10000      # physical (above 64K)
dap# readMemory ispace:0xBA60     # I-space, current PIL
dap# readMemory dspace:0xBA60     # D-space, current PIL
dap# readMemory 0x1000@1          # virtual, PIL 1's page table
dap# readMemory ispace:0xBA60@0   # I-space, PIL 0's page table
dap# readMemory dspace:0x100@1    # D-space, PIL 1's page table
```

**I-space and D-space prefixes** are essential when the kernel runs with
PTM=1 (split I/D mode). In this mode, the same virtual address maps to
different physical memory depending on whether the CPU is fetching an
instruction (I-space, via the PT field of the PCR) or accessing data
(D-space, via the APT field of the PCR).

The `disassemble` command defaults to I-space (since instructions are
always fetched from I-space), but accepts all prefixes for inspection.

The same encoding is accepted by `writeMemory`. Data breakpoints
(`setDataBreakpoints`) use a similar scheme on `dataId`: prefix
`I:`/`D:`/`P:`/`V:` + octal address + optional `@PIL` suffix.

#### `disassemble` (aliases: `da`)
**Purpose**: Disassemble code at memory location.
**Syntax**: `disassemble <memory_reference> [-o offset] [-i instruction_offset] [-c count] [-s]`

The `memory_reference` supports the same `[prefix:]address[@pil]` encoding
as `readMemory`. Default is I-space (instruction fetch page table).

**Examples**:
```bash
dap# disassemble 0x401000       # Disassemble at address (I-space, current PIL)
dap# da main -c 10              # Disassemble 10 instructions at main
dap# da 0x1000@1 -c 5           # Disassemble as PIL 1 sees it
dap# da ispace:0xBA60@0 -c 10   # Overlay code, PIL 0's page table
```

### ⚙️ System & Utility

Commands for system management and debugging assistance.

#### `capabilities` (aliases: `srv`, `server`)
**Purpose**: Show comprehensive DAP server capabilities and protocol compliance.
**Syntax**: `capabilities`
**Examples**:
```bash
dap# srv                   # Quick server info
dap# capabilities          # Full capability report
dap# server                # Alternative alias
```
**Output**: Detailed DAP specification compliance report showing:
- Connection status (works without server connection)
- DAP initialization capabilities
- Supported requests and events
- Current session information
- Protocol compliance details
**Note**: This command works even when not connected to a DAP server.

#### `debugmode` (aliases: `dm`)
**Purpose**: Toggle debug mode for protocol troubleshooting.
**Syntax**: `debugmode`
**Examples**:
```bash
dap# debugmode             # Toggle debug output
dap# dm                    # Short alias
```
**Features**: Shows detailed DAP protocol messages and internal operations.

#### `help` (aliases: `?`, `h`)
**Purpose**: Show command help and documentation.
**Syntax**: `help [command]`
**Examples**:
```bash
dap# help                  # Show all commands
dap# help readMemory       # Detailed help for specific command
dap# ? threads             # Help for threads command
```

#### `exit` (aliases: `q`, `quit`)
**Purpose**: Exit the debugger gracefully.
**Syntax**: `exit`
**Examples**:
```bash
dap# exit                  # Clean exit
dap# quit                  # Alternative
dap# q                     # Short alias
```

## 🧠 Smart Features

### Parameter Validation
Commands validate parameters and provide helpful error messages:
```bash
dap# variables
Error: variables command requires a variables reference (get from scopes)

dap# readMemory
Error: readMemory command requires a memory reference (address or symbol)
```

### Smart Caching
Commands remember previous results for seamless workflows:
```bash
dap# threads               # Caches first thread ID
dap# stackTrace            # Uses cached thread ID automatically
dap# scopes                # Uses cached frame ID from stackTrace
dap# variables             # Uses cached variables reference from scopes
```

### Beautiful Output
All responses use professional formatting:
- **Unicode tables** for structured data (threads, variables, stack traces)
- **Hex dump format** for memory examination
- **Visual indicators** (✅ ❌ ❓) for capability reporting
- **Color-ready output** for enhanced terminal displays

## 📊 Command Workflow Examples

### Basic Debugging Session
```bash
dap# srv                   # Check server capabilities
dap# launch program.exe    # Start debugging
dap# break main.c 42       # Set breakpoint
dap# continue              # Run to breakpoint
dap# threads               # Check available threads
dap# stackTrace            # Show call stack
dap# scopes                # Show variable scopes
dap# variables             # Show all variables
```

### Memory Analysis
```bash
dap# x 0x401000 256        # Examine 256 bytes of memory
dap# disassemble 0x401000  # Disassemble at same address
dap# evaluate *ptr         # Evaluate pointer value
dap# x *ptr 64             # Examine memory at pointer
```

### Advanced Debugging
```bash
dap# debugmode             # Enable debug mode
dap# srv                   # Check what server supports (works offline)
dap# threads               # List all threads
dap# stackTrace 2          # Stack for specific thread
dap# variables 1001        # Variables for specific reference
dap# memory main 128       # Memory at main function
```

## 🔗 Protocol Compliance

All commands follow the [Debug Adapter Protocol](https://microsoft.github.io/debug-adapter-protocol/) specification and provide standard DAP request/response handling with enhanced user experience through:

- Smart parameter validation and caching
- Professional table formatting
- Industry-standard memory examination tools
- Comprehensive capability reporting
- Thread-safe multi-threaded operation

## 💡 Tips

1. **Use short aliases** for faster debugging: `t`, `bt`, `s`, `x`, `c`
2. **Enable debug mode** when troubleshooting: `debugmode`
3. **Check server capabilities** anytime: `srv` (works without connection)
4. **Let smart caching work** - run `threads` → `stackTrace` → `scopes` → `variables` in sequence
5. **Use help extensively** - `help <command>` for detailed information
6. **Memory examination** - start with small chunks (`x addr 16`) then increase size