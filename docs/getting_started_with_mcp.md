# Getting Started with MCP Debugging on ND-100

This guide shows how to start an nd100x debugging session using the MCP DAP server tools. It covers launching the emulator, loading programs, setting breakpoints, stepping through code, and inspecting memory.

## Prerequisites

- nd100x emulator built: `~/repos/nd100x/build/bin/nd100x`
- MCP DAP server installed: `cd ~/repos/libdap/mcp-dap-server && pip install -e .`
- MCP server configured in `~/.claude.json`:

```json
{
  "mcpServers": {
    "dap-debugger": {
      "type": "stdio",
      "command": "python3",
      "args": ["-m", "mcp_dap_server.server"],
      "cwd": "/home/ronny/repos/libdap/mcp-dap-server"
    }
  }
}
```

## Starting nd100x

The nd100x emulator must be running with `--debugger` before MCP tools can connect. Start it in a background shell:

```bash
~/repos/nd100x/build/bin/nd100x --debugger
```

This starts the DAP server on port 4711 (the default). The emulator waits for a debugger connection before executing any code.

**Verify it started**: look for `NDX debugger listening on port 4711...` in the output.

**Port option**: The default port is 4711. To use a different port, use the short flag: `-p 5000`. The long-form `--port=N` has a known argument parsing issue.

**No boot/image flags needed**: When `--debugger` is specified, the emulator skips the normal boot sequence. The program to debug is loaded later via the `debug_launch` MCP tool.

## Connecting and Loading a Program

### Step 1: Connect

```
debug_connect(port=4711)
```

This initializes the DAP session and returns the server's capabilities. Port 4711 is the default.

### Step 2: Launch

The launch command differs between assembly and C programs.

#### Assembly Programs

Assembly programs need the binary (a.out) and the source file. A `.map` file provides line-to-address mapping for source-level debugging.

```
debug_launch(
    program="/path/to/program.out",
    source_file="/path/to/program.s",
    map_file="/path/to/program.map",
    stop_on_entry=true
)
```

- `program` - the assembled/linked a.out binary
- `source_file` - the `.s` assembly source file
- `map_file` - the `.map` file from the assembler/linker (format: `source.s:LINE -> OCTAL_ADDRESS`)

#### C Programs

C programs compiled with `cc -g` and linked with `nd100-ld -m` produce a `.srcmap` file containing function definitions, parameter offsets, local variable offsets, and source line mappings.

```
debug_launch(
    program="/path/to/hello",
    source_file="/path/to/hello.c",
    map_file="/path/to/hello.srcmap",
    stop_on_entry=true
)
```

- `program` - the linked a.out binary (contains STABS debug symbols when compiled with `-g`)
- `source_file` - the `.c` source file
- `map_file` - the `.srcmap` file from `nd100-ld -m` (contains FUNC/PARAM/LOCAL/line entries)

**Key difference**: C programs use `.srcmap` files, which include C-level metadata (function names, parameters, locals) on top of the line-to-address mappings. This enables the "Locals" scope to show C variables and the stack trace to show C function names.

**Example C project location**: `~/repos/ndasm/c/` contains `hello.c`, `hello` (binary), and `hello.srcmap`.

## Identifying Where to Set Breakpoints

Before setting breakpoints, you need to know what addresses or line numbers to target.

### By Source Line Number

Read the source file and pick a line number. Use `debug_set_breakpoints` with the source filename and line numbers:

```
debug_set_breakpoints(source="hello.c", lines=[90, 96])
```

For assembly:
```
debug_set_breakpoints(source="program.s", lines=[8, 18])
```

The debugger resolves line numbers to memory addresses using the loaded map file. If a line number does not correspond to an instruction address, the breakpoint may be adjusted to the nearest valid line. The response includes a `verified` field indicating whether the breakpoint was successfully placed.

### By Memory Address

If you know the octal or hex address, use instruction breakpoints. Addresses are specified as hex strings:

```
debug_set_instruction_breakpoints(addresses=["0x00D5"])
```

To convert between octal (native ND-100) and hex for this tool:
- Octal `000325` = hex `0x00D5` (decimal 213)
- Octal `000112` = hex `0x004A` (decimal 74)

### Finding Addresses from the Map File

The `.srcmap` or `.map` file maps source lines to octal addresses. Read it to plan breakpoints:

```
hello.c:88 -> 000325    (start of main)
hello.c:93 -> 000331    (first function call)
FUNC:sum_to_n -> 000043 (function entry)
```

Multiple source lines can map to the same address (common for variable declarations, loop setup). Setting a breakpoint on any of those lines will break at that shared address.

### Using the Stack Trace

After stopping, `debug_stack_trace()` shows where you are:

```
debug_stack_trace()
-> [
     { name: "main +5 @00325", line: 88, source: "hello.c" },
     { name: "start +0 @00000", line: 10, source: "hello.c" }
   ]
```

### Using Disassembly

To find addresses by examining machine code:

```
debug_disassemble(address="0x00D5", count=10)
```

This shows instructions with their octal opcodes and mnemonics, useful for finding call targets (JPL instructions) or specific code sequences.

## Stepping Through Code

### Granularity

The stepping granularity controls whether you step by source line or by machine instruction:

- `"statement"` or `"line"` - step one **source line** (skips over multiple instructions that belong to the same line)
- `"instruction"` - step one **machine instruction**

For C and assembly source-level debugging, always use `"statement"`:

```
debug_step_over(granularity="statement")
debug_step_in(granularity="statement")
```

Without specifying granularity, stepping defaults to instruction level.

### Step Over (Next Line)

Executes the current source line. If the line contains a function call, the entire call executes and you stop at the next line after the call returns.

```
debug_step_over(granularity="statement")
```

### Step In (Enter Function)

If the current source line contains a function call (JPL instruction), steps into the called function and stops at its first line. If no call is present, behaves like step over.

```
debug_step_in(granularity="statement")
```

### Step Out (Return from Function)

Continues execution until the current function returns, then stops at the caller.

```
debug_step_out()
```

### Continue (Run to Breakpoint)

Runs until the next breakpoint, watchpoint, or program exit:

```
debug_continue()
```

## Source Listing and Disassembly

### Viewing Source Context

The MCP tools do not have a built-in "list" command. To see the source context around the current position:

1. Use `debug_stack_trace()` to get the current file and line number
2. Read the source file directly to see the surrounding code

### Disassembly

To disassemble from the current PC or any address:

```
debug_disassemble(address="0x00D5", count=20)
```

Returns an array of instructions, each with:
- `address` - hex address
- `instruction` - octal opcode and mnemonic (e.g., `"135025 JPL I 25"`)
- `symbol` - function name if the address matches a symbol
- `line` / `source` - source location if available from the map

## Inspecting State

### Registers

```
debug_variables(scope="Registers")
```

Shows the 8 ND-100 registers: STS (status), D, P (program counter), B (base/frame pointer), L (link/return address), A (accumulator), T, X (index). The STS register includes decoded status flags.

### Local Variables (C programs only)

```
debug_variables(scope="Locals")
```

When stopped inside a C function with debug info, shows parameters and local variables with their current values. Parameters are read from `B+2`, `B+3`, etc.; locals from `B-1`, `B-2`, etc.

### Evaluate Expressions

```
debug_evaluate(expression="A")
```

Evaluates register names and returns their value.

## Memory Access

### Reading Memory

```
debug_read_memory(address="0x0100", count=32)
```

Returns a hex dump with ASCII representation. The `count` is in **bytes** (2 bytes per ND-100 word).

### Writing Memory

```
debug_write_memory(address="0x0100", data="00FF01A0")
```

The `data` is a hex string of bytes to write.

### Address Space

Memory read and write operations (`debug_read_memory`, `debug_write_memory`) use **virtual addresses**. The nd100x emulator's memory management system (MMS) translates virtual addresses to physical addresses transparently. If paging is disabled (the typical case for simple test programs), virtual addresses map 1:1 to physical addresses.

## Memory Watchpoints (Data Breakpoints)

Watchpoints monitor memory locations and break when the watched address is accessed. By default, watchpoints operate on **virtual addresses**. An `address_space` parameter allows monitoring **physical addresses** instead.

### Setting Watchpoints (Virtual - Default)

Watch a named symbol:
```
debug_set_data_breakpoints(variables=["counter"], access_type="write")
```

Watch a specific memory address (octal with leading zero, hex with `0x` prefix, or decimal):
```
debug_set_data_breakpoints(variables=["0x40"], access_type="readWrite")
```

Watch multiple locations:
```
debug_set_data_breakpoints(
    variables=["counter", "var_a", "0x1d"],
    access_type="readWrite"
)
```

### Setting Watchpoints (Physical)

To monitor physical memory addresses, add `address_space="physical"`. This is useful when:
- Multiple virtual addresses map to the same physical location (aliasing)
- You want to catch DMA or page table accesses
- You need to monitor memory at the hardware level regardless of MMS mapping

```
debug_set_data_breakpoints(
    variables=["0x40"],
    access_type="write",
    address_space="physical"
)
```

Physical watchpoints trigger on all accesses to the physical address, including those from different virtual address mappings and direct physical memory operations that bypass the MMS.

Physical addresses can be larger than 16 bits (up to 21+ bits for extended memory configurations), so you can watch addresses beyond the 64K-word virtual address space.

### Access Types

- `"write"` - break when memory is written (default)
- `"read"` - break when memory is read
- `"readWrite"` - break on any access

### Important Notes

- Each call **replaces all** previous data breakpoints, both virtual and physical (per DAP spec). To watch multiple locations, include all of them in a single call.
- All watchpoints in a single call share the same `address_space`. To mix virtual and physical watchpoints, you would need separate calls (but note that each call replaces the previous ones).
- The stop occurs at the instruction **after** the memory access, since the CPU executes the read/write before the watchpoint fires.
- Up to 32 simultaneous watchpoints are supported (32 virtual + 32 physical, tracked separately).
- Variable names are resolved by searching all loaded symbol tables (a.out binary symbols, .map file symbols, STABS debug symbols). If no symbol matches, the name is parsed as a numeric address. Symbol resolution works with both virtual and physical address spaces.
- To clear all watchpoints: `debug_set_data_breakpoints(variables=[])`

## Console I/O

The console I/O tools let you interact with the program's terminal -- capture output and send keyboard input. This is essential for debugging interactive programs, automated login sequences, or verifying program output.

### Enabling Console Capture

Before reading any output, enable capture on the terminal device:

```
debug_console_enable(terminal=192)
```

Terminal 192 (octal 0300) is the system console. Other terminals use different addresses (e.g., 224 for terminal 5).

### Reading Output

After continuing execution, read what the program has printed:

```
debug_console_read(timeout=3.0)
-> {"output": "Hello, World!\r\n", "raw_hex": "48656C6C6F..."}
```

The `timeout` parameter controls how long to wait for additional output. Use a longer timeout if the program takes time to produce output (e.g., during boot).

The response contains both `output` (printable text, with non-printable chars replaced by `.`) and `raw_hex` (exact byte values). Use `raw_hex` to detect control characters and escape sequences.

### Sending Input

Send keyboard input to the terminal:

```
debug_console_write(input="root\r")
```

Use `\r` for Enter. For special keys, use hex mode:

```
debug_console_write(input="hex:1B5B41")   # Arrow Up (ESC [ A)
debug_console_write(input="hex:03")        # Ctrl-C
```

### Waiting for a Specific Prompt

A common pattern is waiting for a program to print a specific string (like a login prompt) before sending input. Since `debug_console_read` returns all buffered output, check for the expected text in a loop:

**Example: Automated login sequence**

```
# 1. Connect and launch
debug_connect(port=4711)
debug_launch(program="/path/to/system", stop_on_entry=true)

# 2. Enable console capture
debug_console_enable(terminal=192)

# 3. Let the system boot
debug_continue()

# 4. Wait for "login:" prompt
#    Call debug_console_read repeatedly until the output contains "login:"
debug_console_read(timeout=5.0)
-> {"output": "ND-100 SINTRAN III\r\nlogin: ", ...}
#    Found "login:" in output -- proceed

# 5. Send username + Enter
debug_console_write(input="root\r")

# 6. Wait for password prompt (if any) or shell prompt
debug_console_read(timeout=3.0)
-> {"output": "password: ", ...}

debug_console_write(input="secret\r")

# 7. Wait for shell prompt "#"
debug_console_read(timeout=3.0)
-> {"output": "\r\n# ", ...}
#    Found "#" -- logged in successfully

# 8. Now send commands to the shell
debug_console_write(input="who\r")
debug_console_read(timeout=2.0)
-> {"output": "root     console\r\n# ", ...}
```

**Key points for the wait-and-respond pattern:**

1. **Use `debug_continue()` first** -- the program must be running to produce output. Console capture works while the CPU is executing.
2. **Check output text for your target string** -- `debug_console_read` returns whatever has been buffered. If the expected text hasn't appeared yet, call it again with a timeout.
3. **Each read drains the buffer** -- once read, output is consumed. Subsequent reads return only new output since the last read.
4. **Timeout is important** -- set it long enough for slow operations (boot: 5-10s) and short for fast responses (command output: 1-2s).
5. **`\r` is Enter** -- ND-100 terminals use CR (`\r`) as the line terminator for input. Always append `\r` when sending commands.

### Disabling Console Capture

When done, disable capture to restore normal terminal operation:

```
debug_console_enable(terminal=192, enable=false)
```

## Multiple LLM Sessions (Parallel Debugging)

Multiple AI assistants can debug different nd100x emulators simultaneously. Each MCP client (e.g. separate terminal sessions) spawns its own MCP server process, so sessions are fully isolated.

### How It Works

MCP uses stdio transport, which is inherently 1:1. Each MCP client spawns its own `mcp-dap-server` process with an independent `DAPDebugger` instance:

```
LLM-A  -->  MCP process A  -->  debug_connect(port=4711)  -->  nd100x #1
LLM-B  -->  MCP process B  -->  debug_connect(port=4712)  -->  nd100x #2
LLM-C  -->  MCP process C  -->  debug_connect(port=4713)  -->  nd100x #3
```

No code changes or special configuration needed -- this works out of the box.

### Setup

1. Start multiple nd100x emulators on different ports:

```bash
# Terminal 1
~/repos/nd100x/build/bin/nd100x --debugger -p 4711

# Terminal 2
~/repos/nd100x/build/bin/nd100x --debugger -p 4712

# Terminal 3
~/repos/nd100x/build/bin/nd100x --debugger -p 4713
```

2. Each LLM uses the same MCP server configuration (from `~/.claude.json`). No per-LLM config changes needed.

3. Each LLM connects to its assigned emulator by specifying the port:

```
debug_connect(port=4711)   # LLM-A connects to emulator #1
debug_connect(port=4712)   # LLM-B connects to emulator #2
debug_connect(port=4713)   # LLM-C connects to emulator #3
```

Each session is completely independent -- breakpoints, execution state, memory writes, and console I/O are isolated per emulator.

## Ending a Session

```
debug_disconnect(terminate=true)
```

This disconnects from the DAP server. With `terminate=true` (default), it also signals the debuggee to stop.

To fully stop the emulator, kill the nd100x process separately.

## Quick Reference

| Task | Command |
|------|---------|
| Connect | `debug_connect(port=4711)` |
| Launch (asm) | `debug_launch(program="prog.out", source_file="prog.s", map_file="prog.map")` |
| Launch (C) | `debug_launch(program="hello", source_file="hello.c", map_file="hello.srcmap")` |
| Breakpoint (line) | `debug_set_breakpoints(source="hello.c", lines=[90])` |
| Breakpoint (addr) | `debug_set_instruction_breakpoints(addresses=["0x00D5"])` |
| Watchpoint (virtual) | `debug_set_data_breakpoints(variables=["counter"], access_type="write")` |
| Watchpoint (physical) | `debug_set_data_breakpoints(variables=["0x40"], access_type="write", address_space="physical")` |
| Continue | `debug_continue()` |
| Step over | `debug_step_over(granularity="statement")` |
| Step in | `debug_step_in(granularity="statement")` |
| Step out | `debug_step_out()` |
| Stack trace | `debug_stack_trace()` |
| Registers | `debug_variables(scope="Registers")` |
| Locals | `debug_variables(scope="Locals")` |
| Disassemble | `debug_disassemble(address="0x00D5", count=20)` |
| Read memory | `debug_read_memory(address="0x0100", count=32)` |
| Write memory | `debug_write_memory(address="0x0100", data="00FF")` |
| Console enable | `debug_console_enable(terminal=192)` |
| Console read | `debug_console_read(timeout=3.0)` |
| Console write | `debug_console_write(input="root\r")` |
| Console disable | `debug_console_enable(terminal=192, enable=false)` |
| Disconnect | `debug_disconnect()` |
