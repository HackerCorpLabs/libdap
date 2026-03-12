# MCP DAP Server

A Python MCP (Model Context Protocol) server that provides debugging tools by connecting to any DAP (Debug Adapter Protocol) server over TCP. Built for use with AI coding assistants, enabling interactive debugging sessions through structured tool calls.

## Architecture

```
AI Assistant  <-- MCP (stdio) -->  MCP DAP Server  <-- DAP (TCP) -->  DAP Server
                                   (this project)                     (e.g. nd100x, VS Code debug adapter)
```

The MCP server is a long-lived process that maintains stateful debugging sessions. It speaks DAP over TCP to the debug server and exposes 20 tools via MCP's stdio transport. All session state (connection, breakpoints, execution position) persists across tool calls.

## Requirements

- Python 3.10+
- `mcp` package (>= 1.0)

## Installation

```bash
cd mcp-dap-server
pip install -e .
```

## Configuration

### For AI Coding Assistants

Add to your assistant's MCP server configuration (e.g. `~/.claude.json`):

```json
{
  "mcpServers": {
    "dap-debugger": {
      "type": "stdio",
      "command": "python3",
      "args": ["-m", "mcp_dap_server.server"],
      "cwd": "/path/to/libdap/mcp-dap-server"
    }
  }
}
```

### Standalone

```bash
python3 -m mcp_dap_server.server
```

The server communicates via stdin/stdout using the MCP protocol. It does not start a DAP server itself - you need a running DAP server to connect to.

## Tools Reference

### Session Management

#### `debug_connect`
Connect to a DAP debug server and initialize the session. Must be called before any other debug commands.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | string | `"127.0.0.1"` | DAP server hostname |
| `port` | integer | `4711` | DAP server port |

Returns: Server capabilities.

#### `debug_launch`
Launch a program for debugging. The program path is sent to the DAP server which loads it.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `program` | string | Yes | Path to the program to debug |
| `stop_on_entry` | boolean | No (default: true) | Stop at program entry point |
| `source_file` | string | No | Path to source file for source-level debugging |
| `map_file` | string | No | Path to .map file for source line mapping |

Returns: Launch status and initial stopped event (if stop_on_entry is true).

#### `debug_disconnect`
Disconnect from the DAP server and optionally terminate the debuggee.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `terminate` | boolean | `true` | Terminate the debuggee |

#### `debug_status`
Get the current debugger status: connection state, program, breakpoints, and any pending events.

No parameters. Returns: Connection state, loaded program, active breakpoints, pending events.

### Execution Control

#### `debug_continue`
Continue program execution until the next breakpoint, exception, or program exit.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `thread_id` | integer | `1` | Thread to continue |

Returns: Stop reason, location, and any output events.

#### `debug_step_in`
Step into the next function call or instruction.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `thread_id` | integer | `1` | Thread to step |
| `granularity` | string | - | `"statement"`, `"line"`, or `"instruction"` |

Returns: New location after stepping.

#### `debug_step_over`
Step over the current line/instruction (execute without entering function calls).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `thread_id` | integer | `1` | Thread to step |
| `granularity` | string | - | `"statement"`, `"line"`, or `"instruction"` |

Returns: New location after stepping.

#### `debug_step_out`
Step out of the current function.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `thread_id` | integer | `1` | Thread to step out |

Returns: New location after returning from the function.

#### `debug_step_back`
Step back to the previous execution point (requires reverse execution support from the DAP server).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `thread_id` | integer | `1` | Thread to step back |

#### `debug_pause`
Pause program execution.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `thread_id` | integer | `1` | Thread to pause |

### Breakpoints

#### `debug_set_breakpoints`
Set source breakpoints for a file. Merges with existing breakpoints for that file.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | string | Yes | Source file path |
| `lines` | array[int] | Yes | Line numbers |
| `conditions` | array[string] | No | Optional condition per breakpoint |

Returns: List of breakpoints with verified status.

The MCP server maintains per-file breakpoint state internally. DAP's `setBreakpoints` replaces all breakpoints for a source file, so this tool merges new breakpoints with existing ones. This means you can add breakpoints incrementally without clobbering previous ones.

#### `debug_set_instruction_breakpoints`
Set breakpoints at specific memory addresses.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `addresses` | array[string] | Yes | Memory addresses (hex strings like `"0x1000"`) |
| `conditions` | array[string] | No | Optional condition per breakpoint |

Returns: List of breakpoints with verified status.

#### `debug_set_data_breakpoints`
Set data breakpoints (memory watchpoints). These monitor memory locations and break when the watched address is accessed. Replaces all previously set data breakpoints.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `variables` | array[string] | Yes | Variable names or memory addresses to watch (see below) |
| `access_type` | string | No (default: `"write"`) | `"read"`, `"write"`, or `"readWrite"` |

Returns: List of breakpoints with verified status.

**How it works**: For each entry in the `variables` array, the MCP server sends a DAP `dataBreakpointInfo` request to the debug server. The server resolves the name to a memory address and returns a `dataId`. Then `setDataBreakpoints` is called with all valid dataIds. If a variable name cannot be resolved, it is silently skipped.

**Variable resolution** (nd100x): The debug server resolves variable names in this order:
1. **Symbol lookup** - searches all loaded symbol tables (a.out binary symbols, `.map` file symbols, STABS debug symbols) for an exact name match
2. **Numeric address** - if no symbol matches, parses as a number: hex (`0x1d`), octal with leading zero (`035`), or decimal (`29`)

If neither resolves, the variable is reported as unsupported and skipped.

**Access types**:
- `"write"` - break when memory is written to (default)
- `"read"` - break when memory is read from
- `"readWrite"` - break on any access

**Examples**:
```
# Watch a named variable for writes
debug_set_data_breakpoints(variables=["counter"], access_type="write")

# Watch multiple variables for any access
debug_set_data_breakpoints(variables=["var_a", "var_b"], access_type="readWrite")

# Watch a specific memory address (octal) for reads
debug_set_data_breakpoints(variables=["0100"], access_type="read")

# Watch a hex address for writes
debug_set_data_breakpoints(variables=["0x40"], access_type="write")

# Mix symbols and addresses
debug_set_data_breakpoints(variables=["counter", "0x1d"], access_type="readWrite")
```

**Important**: Each call replaces all previous data breakpoints (per DAP spec). To watch multiple locations, include all of them in a single call.

### Inspection

#### `debug_stack_trace`
Get the call stack for a thread.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `thread_id` | integer | `1` | Thread ID |

Returns: Array of stack frames with id, name, source file, line, and instruction pointer.

#### `debug_variables`
Get variables for a scope.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scope` | string/int | - | Scope name (e.g., `"Registers"`, `"Locals"`) or numeric variablesReference. Omit for all scopes. |
| `frame_id` | integer | `0` | Stack frame ID |
| `depth` | integer | `1` | Recursion depth for expanding child variables |

Returns: Variables with name, value, type, and child reference info.

#### `debug_evaluate`
Evaluate an expression in the debuggee context.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `expression` | string | Yes | Expression to evaluate |
| `frame_id` | integer | No (default: 0) | Stack frame ID for context |

Returns: Result value, type, and optional variable reference.

#### `debug_threads`
Get list of threads. No parameters.

Returns: Array of thread objects with id and name.

### Memory and Disassembly

#### `debug_read_memory`
Read memory from the debuggee. Returns hex dump with ASCII representation.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | Yes | Memory address (hex string like `"0x1000"`) |
| `count` | integer | No (default: 256) | Number of bytes to read |

Returns: Hex dump lines, byte count, and raw base64 data.

#### `debug_write_memory`
Write memory to the debuggee.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | Yes | Memory address (hex string like `"0x1000"`) |
| `data` | string | Yes | Hex string of bytes to write (e.g., `"48454C4C4F"`) |

Returns: Bytes written and offset.

#### `debug_disassemble`
Disassemble instructions at a memory address.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | Yes | Memory address (hex string like `"0x1000"`) |
| `count` | integer | No (default: 20) | Number of instructions |

Returns: Array of instructions with address, mnemonic, bytes, symbol, and source location.

## File Structure

```
mcp-dap-server/
  pyproject.toml              Package definition, dependencies
  mcp_dap_server/
    __init__.py
    server.py                 MCP server entry point, tool registration, dispatch
    dap_connection.py         DAP TCP connection, Content-Length framing, request/response matching
    tools.py                  DAPDebugger class - stateful tool implementations
    types.py                  Response formatting helpers, address parsing, memory decoding
```

### `dap_connection.py`
Async TCP connection to DAP servers. Handles the `Content-Length: N\r\n\r\n{json}` wire protocol. Features:
- Auto-incrementing sequence numbers for request/response matching
- `asyncio.Future`-based response correlation
- Background read loop that dispatches responses and buffers events
- `wait_for_event()` with configurable timeout for execution commands
- `drain_events()` to collect buffered output/thread/module events

### `tools.py`
The `DAPDebugger` class is a singleton that persists across all MCP tool calls within a session. Key design decisions:
- **Event waiting**: After `continue`/`step*` commands, waits for a `stopped`/`terminated`/`exited` event before returning. Uses a 2-second timeout for step commands with a fallback to querying `stackTrace` for current location.
- **Breakpoint merging**: Source breakpoints are tracked per-file. New breakpoints merge with existing ones since DAP's `setBreakpoints` replaces all breakpoints for a source.
- **Stale event draining**: Before executing step/continue, drains any leftover events from previous operations.

### `types.py`
Response formatters that transform raw DAP responses into clean structured data. Notable helpers:
- `_parse_address()`: Handles hex (`0x...`), bare octal (ND-100 style `000022`), and decimal addresses
- `_decode_memory_data()`: Auto-detects hex-encoded vs base64-encoded memory data
- `format_memory_read()`: Produces hex dump with ASCII representation
- `format_stack_trace()`: Extracts frames with source, line, and instruction pointer

## Usage Examples

### Basic debugging session

```
1. debug_connect(host="127.0.0.1", port=4711)
2. debug_launch(program="/path/to/program.out", source_file="/path/to/source.s", map_file="/path/to/source.map")
3. debug_set_breakpoints(source="/path/to/source.s", lines=[8, 18])
4. debug_continue()                    -- runs to first breakpoint
5. debug_stack_trace()                 -- inspect call stack
6. debug_variables(scope="Registers")  -- inspect CPU registers
7. debug_read_memory(address="0x0")    -- read memory at address 0
8. debug_step_in()                     -- step into function call
9. debug_step_out()                    -- return to caller
10. debug_disconnect()                 -- end session
```

### Memory watchpoint session

Monitor memory locations to detect reads and writes. Useful for tracking when and where variables are modified.

```
1. debug_connect(host="127.0.0.1", port=4711)
2. debug_launch(program="/path/to/mem.out", source_file="/path/to/mem.s", map_file="/path/to/mem.map")
3. debug_set_data_breakpoints(          -- set watchpoints by symbol name
     variables=["counter", "var_a"],
     access_type="readWrite"
   )
4. debug_continue()                     -- runs until watched memory is accessed
   -> stops with reason "data breakpoint" at the instruction after the access
5. debug_variables(scope="Registers")   -- check register state (A register has the value)
6. debug_read_memory(address="0x20")    -- read the watched memory location directly
7. debug_continue()                     -- continue to next access
   -> each read/write to the watched address triggers a stop
8. debug_set_data_breakpoints(          -- change to write-only monitoring
     variables=["counter"],
     access_type="write"
   )
9. debug_continue()                     -- now only stops on writes, not reads
10. debug_set_data_breakpoints(         -- clear all watchpoints (empty array)
      variables=[]
    )
11. debug_disconnect()
```

**Note**: The stop occurs at the instruction *after* the memory access, since the CPU has already executed the read/write instruction when the watchpoint fires. Check the `EA` (Effective Address) register to confirm which address was accessed.

## ND-100 Specific Notes

When debugging ND-100 programs (via the nd100x emulator):

- **Addresses are octal**: The nd100x DAP server returns addresses in octal without prefix (e.g., `000022`). The MCP server's `_parse_address()` detects bare octal strings (all digits 0-7, length >= 4) and handles them correctly.
- **Memory encoding**: The nd100x server sends base64-encoded memory data (per DAP spec). The mock server in libdap sends hex-encoded data. Both formats are auto-detected.
- **Map files**: For source-level debugging of assembly programs, pass the `.map` file generated by the assembler. The map file format is: `/path/to/source.s:LINE -> OCTAL_ADDRESS`
- **JPL/EXIT calling convention**: The stack trace correctly tracks JPL (Jump and Link) calls and EXIT returns, showing the full call chain.
- **Register scopes**: Variables with scope `"CPU Registers"` shows the 8 ND-100 registers (STS, D, P, B, L, A, T, X) with decoded status flags.
- **Memory watchpoints**: The nd100x emulator supports data breakpoints (watchpoints) on any 16-bit memory address with read, write, or readWrite access types. Up to 32 simultaneous watchpoints are supported. Variables can be specified by symbol name (looked up across all loaded symbol tables) or by numeric address. The `dataId` used internally is the octal address string (e.g., `"000040"`).

## Troubleshooting

**MCP server not showing up**: Ensure the config is in `~/.claude.json` (not in `.claude/settings.local.json`). The `type` must be `"stdio"`.

**Connection refused**: Make sure the DAP server is running and listening on the configured port (default 4711).

**Step commands timing out**: Step commands use a 2-second timeout waiting for a `stopped` event. If the DAP server doesn't send one, the MCP server falls back to querying the stack trace for the current location.

**Breakpoints not verified**: Ensure a `.map` file or symbol table is loaded. Without source-to-address mapping, source breakpoints cannot be resolved. Use instruction breakpoints (`debug_set_instruction_breakpoints`) as an alternative.

**Data breakpoints not supported**: The `debug_set_data_breakpoints` tool returns an error if the DAP server does not advertise `supportsDataBreakpoints`. Check the capabilities returned by `debug_connect`. If the server supports it but a specific variable fails, the symbol name may not exist in any loaded symbol table - try using a numeric address instead.

**Watchpoint stops at wrong line**: Data breakpoint stops occur at the instruction *after* the memory access. This is expected - the CPU executes the read/write, the watchpoint fires, and the debugger stops before the next instruction. Look at the preceding instruction or the `EA` register to see what address was accessed.
