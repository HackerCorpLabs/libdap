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
Set data breakpoints (watchpoints) on variables.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `variables` | array[string] | Yes | Variable names to watch |
| `access_type` | string | No (default: `"write"`) | `"read"`, `"write"`, or `"readWrite"` |

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

## Usage Example

A typical debugging session:

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

## ND-100 Specific Notes

When debugging ND-100 programs (via the nd100x emulator):

- **Addresses are octal**: The nd100x DAP server returns addresses in octal without prefix (e.g., `000022`). The MCP server's `_parse_address()` detects bare octal strings (all digits 0-7, length >= 4) and handles them correctly.
- **Memory encoding**: The nd100x server sends base64-encoded memory data (per DAP spec). The mock server in libdap sends hex-encoded data. Both formats are auto-detected.
- **Map files**: For source-level debugging of assembly programs, pass the `.map` file generated by the assembler. The map file format is: `/path/to/source.s:LINE -> OCTAL_ADDRESS`
- **JPL/EXIT calling convention**: The stack trace correctly tracks JPL (Jump and Link) calls and EXIT returns, showing the full call chain.
- **Register scopes**: Variables with scope `"CPU Registers"` shows the 8 ND-100 registers (STS, D, P, B, L, A, T, X) with decoded status flags.

## Troubleshooting

**MCP server not showing up**: Ensure the config is in `~/.claude.json` (not in `.claude/settings.local.json`). The `type` must be `"stdio"`.

**Connection refused**: Make sure the DAP server is running and listening on the configured port (default 4711).

**Step commands timing out**: Step commands use a 2-second timeout waiting for a `stopped` event. If the DAP server doesn't send one, the MCP server falls back to querying the stack trace for the current location.

**Breakpoints not verified**: Ensure a `.map` file or symbol table is loaded. Without source-to-address mapping, source breakpoints cannot be resolved. Use instruction breakpoints (`debug_set_instruction_breakpoints`) as an alternative.
