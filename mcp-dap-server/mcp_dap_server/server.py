"""MCP server for DAP debugging.

Provides tools for connecting to a DAP debug server, controlling
execution, setting breakpoints, and inspecting program state.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .tools import DAPDebugger

logger = logging.getLogger(__name__)

# Single global debugger instance (stateful across tool calls)
debugger = DAPDebugger()

app = Server("dap-debugger")


def _result(data: dict | list) -> list[TextContent]:
    """Convert a result dict/list to MCP text content."""
    return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # Session Management
        Tool(
            name="debug_connect",
            description="Connect to a DAP debug server and initialize the session. Must be called before any other debug commands.",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {"type": "string", "default": "127.0.0.1", "description": "DAP server hostname"},
                    "port": {"type": "integer", "default": 4711, "description": "DAP server port"},
                },
            },
        ),
        Tool(
            name="debug_launch",
            description="Launch a program for debugging. The program path is sent to the DAP server which loads it.",
            inputSchema={
                "type": "object",
                "properties": {
                    "program": {"type": "string", "description": "Path to the program to debug"},
                    "stop_on_entry": {"type": "boolean", "default": True, "description": "Stop at program entry point"},
                    "source_file": {"type": "string", "description": "Path to source file for source-level debugging"},
                    "map_file": {"type": "string", "description": "Path to .srcmap file for source-level debugging (C and assembly source lines, C functions, parameters, local variables)"},
                    "text_start": {"type": "integer", "description": "Text segment load address (e.g. 0x1000 for kernel linked with -T 010000). If omitted, text loads at address 0."},
                },
                "required": ["program"],
            },
        ),
        Tool(
            name="debug_attach",
            description="Attach to an already-running debuggee (e.g. a live emulator) instead of launching a program. "
                        "Sends configurationDone and, by default, pauses so the target can be inspected. Call debug_connect first.",
            inputSchema={
                "type": "object",
                "properties": {
                    "source_file": {"type": "string", "description": "Optional source file for source-level debugging"},
                    "map_file": {"type": "string", "description": "Optional .srcmap file for symbols"},
                    "stop": {"type": "boolean", "default": True, "description": "Pause the target after attaching so it can be inspected"},
                },
            },
        ),
        Tool(
            name="debug_disconnect",
            description="Disconnect from the DAP server and optionally terminate the debuggee.",
            inputSchema={
                "type": "object",
                "properties": {
                    "terminate": {"type": "boolean", "default": True, "description": "Terminate the debuggee"},
                },
            },
        ),
        Tool(
            name="debug_status",
            description="Get the current debugger status: connection state, program, breakpoints, and any pending events.",
            inputSchema={"type": "object", "properties": {}},
        ),
        # Execution Control
        Tool(
            name="debug_continue",
            description="Continue program execution until the next breakpoint, exception, or program exit.",
            inputSchema={
                "type": "object",
                "properties": {
                    "thread_id": {"type": "integer", "default": 1, "description": "Thread to continue"},
                },
            },
        ),
        Tool(
            name="debug_step_in",
            description="Step into the next function call or instruction.",
            inputSchema={
                "type": "object",
                "properties": {
                    "thread_id": {"type": "integer", "default": 1},
                    "granularity": {"type": "string", "enum": ["statement", "line", "instruction"], "description": "Step granularity"},
                },
            },
        ),
        Tool(
            name="debug_step_over",
            description="Step over the current line/instruction (execute without entering function calls).",
            inputSchema={
                "type": "object",
                "properties": {
                    "thread_id": {"type": "integer", "default": 1},
                    "granularity": {"type": "string", "enum": ["statement", "line", "instruction"], "description": "Step granularity"},
                },
            },
        ),
        Tool(
            name="debug_step_out",
            description="Step out of the current function.",
            inputSchema={
                "type": "object",
                "properties": {
                    "thread_id": {"type": "integer", "default": 1},
                },
            },
        ),
        Tool(
            name="debug_pause",
            description="Pause program execution.",
            inputSchema={
                "type": "object",
                "properties": {
                    "thread_id": {"type": "integer", "default": 1},
                },
            },
        ),
        # Breakpoints
        Tool(
            name="debug_set_breakpoints",
            description="Set source breakpoints for a file. Merges with existing breakpoints for that file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "Source file path"},
                    "lines": {"type": "array", "items": {"type": "integer"}, "description": "Line numbers"},
                    "conditions": {"type": "array", "items": {"type": "string"}, "description": "Optional condition per breakpoint"},
                },
                "required": ["source", "lines"],
            },
        ),
        Tool(
            name="debug_set_instruction_breakpoints",
            description="Set breakpoints at specific memory addresses.",
            inputSchema={
                "type": "object",
                "properties": {
                    "addresses": {"type": "array", "items": {"type": "string"}, "description": "Memory addresses (hex strings like '0x1000')"},
                    "conditions": {"type": "array", "items": {"type": "string"}, "description": "Optional condition per breakpoint"},
                },
                "required": ["addresses"],
            },
        ),
        Tool(
            name="debug_set_data_breakpoints",
            description=(
                "Set data breakpoints (watchpoints). Watches memory addresses OR CPU registers: "
                "pass a register name (e.g. 'USP') to break on a register, with an optional "
                "per-variable condition supporting value and bit forms (e.g. '== 0x50000204', "
                "'bit 27 -> 1'). For a single register, debug_watch_register is simpler. "
                "Replaces the entire data-breakpoint set."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "variables": {"type": "array", "items": {"type": "string"}, "description": "Variable names to watch. A CPU register name (e.g. 'USP') becomes a register watch."},
                    "access_type": {"type": "string", "enum": ["read", "write", "readWrite"], "default": "write"},
                    "address_space": {"type": "string", "enum": ["virtual", "physical"], "default": "virtual", "description": "Address space: virtual (default) or physical"},
                    "conditions": {"type": "array", "items": {"type": "string"}, "description": "Optional condition per variable (by index). For register watches: '' (any change), '== 0x50000204', '!= N'/'< N'/'>= N', 'bit 27 -> 1', 'bit 27 -> 0', 'bit 27 changed'."},
                },
                "required": ["variables"],
            },
        ),
        Tool(
            name="debug_watch_register",
            description=(
                "Watch a single CPU register: break when it changes, matches a value, or a bit "
                "flips. Examples — register 'USP' with condition: '' (break on any change), "
                "'== 0x50000204' (equals; also != < > <= >=), 'bit 27 -> 1' (bit goes 0->1), "
                "'bit 27 -> 0' (goes 1->0), 'bit 27 changed' (either edge). The condition is "
                "parsed by the debug server. NOTE: replaces the data-breakpoint set — use "
                "debug_set_data_breakpoints to keep several watches at once."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "register": {"type": "string", "description": "CPU register name, e.g. 'USP', 'D0', 'A'."},
                    "condition": {"type": "string", "default": "", "description": "Break condition (see examples). Empty = break on any change."},
                },
                "required": ["register"],
            },
        ),
        Tool(
            name="debug_set_function_breakpoints",
            description="Set breakpoints on functions by name. Replaces all previous function breakpoints.",
            inputSchema={
                "type": "object",
                "properties": {
                    "names": {"type": "array", "items": {"type": "string"}, "description": "Function names to break on"},
                    "conditions": {"type": "array", "items": {"type": "string"}, "description": "Optional condition per breakpoint"},
                },
                "required": ["names"],
            },
        ),
        # Inspection
        Tool(
            name="debug_stack_trace",
            description="Get the call stack for a thread.",
            inputSchema={
                "type": "object",
                "properties": {
                    "thread_id": {"type": "integer", "default": 1},
                },
            },
        ),
        Tool(
            name="debug_variables",
            description="Get variables for a scope. Scope can be a name like 'Locals', 'Registers', 'Memory', or a numeric variablesReference. Omit scope to get all scopes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scope": {"description": "Scope name (e.g., 'Registers', 'Locals') or numeric reference. Omit for all."},
                    "frame_id": {"type": "integer", "default": 0, "description": "Stack frame ID"},
                    "depth": {"type": "integer", "default": 1, "description": "Recursion depth for expanding child variables"},
                },
            },
        ),
        Tool(
            name="debug_evaluate",
            description="Evaluate an expression in the debuggee context.",
            inputSchema={
                "type": "object",
                "properties": {
                    "expression": {"type": "string", "description": "Expression to evaluate"},
                    "frame_id": {"type": "integer", "default": 0, "description": "Stack frame ID for context"},
                },
                "required": ["expression"],
            },
        ),
        Tool(
            name="debug_add_watch",
            description="Add an expression to the persistent watch list (re-evaluated together via debug_evaluate_watches). "
                        "Convenience over debug_evaluate; mirrors the GUI Watch panel.",
            inputSchema={
                "type": "object",
                "properties": {
                    "expression": {"type": "string", "description": "Expression to watch (e.g. a register name or symbol)"},
                },
                "required": ["expression"],
            },
        ),
        Tool(
            name="debug_remove_watch",
            description="Remove the watch expression at the given index (see debug_evaluate_watches output order).",
            inputSchema={
                "type": "object",
                "properties": {
                    "index": {"type": "integer", "description": "Zero-based index of the watch to remove"},
                },
                "required": ["index"],
            },
        ),
        Tool(
            name="debug_clear_watches",
            description="Remove all watch expressions.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="debug_evaluate_watches",
            description="Evaluate every watch expression in one call and return their current values.",
            inputSchema={
                "type": "object",
                "properties": {
                    "frame_id": {"type": "integer", "default": 0, "description": "Stack frame for evaluation context"},
                },
            },
        ),
        Tool(
            name="debug_threads",
            description="Get list of threads.",
            inputSchema={"type": "object", "properties": {}},
        ),
        # Memory & Disassembly
        #
        # Address encoding for all memory/disassembly tools:
        #   [prefix:]address[@pil]
        #
        # Prefixes (optional, default=virtual):
        #   phys:   - Physical address (bypass MMU)
        #   ispace: - I-space (instruction page table, PT field of PCR)
        #   dspace: - D-space (data page table, APT field of PCR)
        #   virt:   - Virtual address (explicit default)
        #   Short forms: P:, I:, D:, V:
        #
        # @PIL suffix (optional, default=current PIL):
        #   @N where N=0-15 selects which PIL's page table to use.
        #   Useful for inspecting user process memory (PIL 1) while
        #   stopped in kernel (PIL 0 or 14).
        #
        # Examples:
        #   "0x1000"           - virtual, current PIL
        #   "ispace:0xBA60"    - I-space (overlay code), current PIL
        #   "dspace:0xBA60@0"  - D-space, PIL 0's page table
        #   "0x1000@1"         - virtual, PIL 1's page table
        #   "phys:0x10000"     - physical (PIL ignored)
        #
        Tool(
            name="debug_read_memory",
            description="Read memory from the debuggee. Returns hex dump. "
                        "Address format: [prefix:]address[@pil]. "
                        "Prefixes: phys: (physical), ispace: (instruction PT), dspace: (data PT). "
                        "Append @N (N=0-15) to read via a specific PIL's page table. "
                        "Examples: '0x1000', 'ispace:0xBA60', 'dspace:0xBA60@0', 'phys:0x10000'.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Memory address: [prefix:]hex_addr[@pil]. "
                            "Prefixes: phys:/P:, ispace:/I:, dspace:/D: (default: virtual). "
                            "Suffix @N: use PIL N's page table (default: current PIL).",
                    },
                    "count": {"type": "integer", "default": 256, "description": "Number of bytes to read"},
                },
                "required": ["address"],
            },
        ),
        Tool(
            name="debug_write_memory",
            description="Write memory to the debuggee. "
                        "Address format: [prefix:]address[@pil]. "
                        "Prefixes: phys:, ispace:, dspace:. Suffix @N for specific PIL.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Memory address: [prefix:]hex_addr[@pil]. "
                            "Prefixes: phys:/P:, ispace:/I:, dspace:/D: (default: virtual). "
                            "Suffix @N: use PIL N's page table (default: current PIL).",
                    },
                    "data": {"type": "string", "description": "Hex string of bytes to write (e.g., '48454C4C4F')"},
                },
                "required": ["address", "data"],
            },
        ),
        Tool(
            name="debug_disassemble",
            description="Disassemble instructions at a memory address. "
                        "Address format: [prefix:]address[@pil]. "
                        "Prefixes: ispace: (default for disassembly), dspace:, phys:. "
                        "Suffix @N for specific PIL's page table. "
                        "Examples: '0x1000', '0x1000@1' (PIL 1's view), 'ispace:0xBA60@0'.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Memory address: [prefix:]hex_addr[@pil]. "
                            "Prefixes: ispace:/I: (default), dspace:/D:, phys:/P:. "
                            "Suffix @N: use PIL N's page table (default: current PIL).",
                    },
                    "count": {"type": "integer", "default": 20, "description": "Number of instructions"},
                },
                "required": ["address"],
            },
        ),
        # Console I/O
        Tool(
            name="debug_console_enable",
            description="Enable or disable console capture on a terminal device. When enabled, program output (characters written by the CPU) is captured and available via debug_console_read. Default terminal 192 (octal 0300 = system console).",
            inputSchema={
                "type": "object",
                "properties": {
                    "terminal": {"type": "integer", "default": 192, "description": "Terminal IOX base address in decimal. Console=192 (0300 octal), Terminal 5=224 (0340 octal)"},
                    "enable": {"type": "boolean", "default": True, "description": "true to enable capture, false to disable"},
                },
            },
        ),
        Tool(
            name="debug_console_write",
            description="Send keyboard input to a terminal. Use \\r for Enter, \\n for LF, \\t for Tab. For raw bytes prefix with 'hex:' e.g. 'hex:1B5B41' sends ESC[A (arrow up). Special chars: Enter=\\r, Escape=\\u001b, Ctrl-C=\\u0003, Ctrl-D=\\u0004.",
            inputSchema={
                "type": "object",
                "properties": {
                    "input": {"type": "string", "description": "Text to send, or 'hex:AABB...' for raw bytes"},
                    "terminal": {"type": "integer", "default": 192, "description": "Terminal IOX address (decimal)"},
                },
                "required": ["input"],
            },
        ),
        Tool(
            name="debug_console_read",
            description="Read buffered console output. Returns text captured since last read (or since console capture was enabled). Call debug_console_enable first. Returns both printable text and raw hex bytes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timeout": {"type": "number", "default": 2.0, "description": "Seconds to wait for additional output"},
                },
            },
        ),
        # CPU execution tracing (RetroCore-custom DAP extension)
        #
        # The CPU records the last N retired instructions into a circular ring
        # buffer. After a breakpoint or crash, read the ring back to see exactly
        # how execution reached the current point. This is the supported substitute
        # for reverse execution (stepBack/reverseContinue are never supported).
        Tool(
            name="debug_set_cpu_tracing",
            description="Enable/disable CPU execution tracing and (re-)allocate the trace ring buffer "
                        "(RetroCore-custom). Turn tracing on and size the ring, then run to a breakpoint "
                        "and read it back with debug_get_cpu_trace_ring. Forwards to the DAP 'setCpuTracing' command.",
            inputSchema={
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean", "description": "Master trace switch. Omit to leave unchanged."},
                    "ring_capacity": {"type": "integer", "description": "Ring-buffer capacity (number of instructions to retain). 0 disables the ring; omit to leave it unchanged."},
                    "pc_filter": {"type": "integer", "description": "Optional single PC to trace exclusively (all other instructions are skipped). Omit/null to clear the filter and trace everything."},
                },
            },
        ),
        Tool(
            name="debug_get_cpu_trace_ring",
            description="Read back the CPU trace ring buffer: the last N retired instructions, oldest-first "
                        "(RetroCore-custom). Each entry has pc, opCode, opCodeName (bare mnemonic), and text "
                        "(the full formatted disassembly+registers line). Forwards to the DAP 'getCpuTraceRing' command.",
            inputSchema={
                "type": "object",
                "properties": {
                    "max_entries": {"type": "integer", "default": 0, "description": "Max entries to return, most-recent N (0 = all retained)"},
                },
            },
        ),
        # Symbol listing (custom DAP extension)
        Tool(
            name="debug_symbol_list",
            description="List symbols from the debug target. Returns symbol names, addresses, types (function/label/variable), and optional source locations. Symbols are cached locally after first fetch; filtering and paging are applied client-side.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {"type": "string", "default": "", "description": "Filter symbols by name (case-insensitive substring match)"},
                    "symbolType": {"type": "integer", "default": 0, "description": "0=all, 1=functions, 2=labels, 3=variables"},
                    "offset": {"type": "integer", "default": 0, "description": "Start offset for paging"},
                    "count": {"type": "integer", "default": 0, "description": "Max symbols to return (0=all)"},
                },
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        result = await _dispatch(name, arguments)
        return _result(result)
    except Exception as exc:
        import traceback
        tb = traceback.format_exc()
        logger.exception("Tool %s failed", name)
        return _result({"error": True, "message": str(exc), "traceback": tb})


async def _dispatch(name: str, args: dict) -> dict | list:
    """Route tool calls to debugger methods."""
    match name:
        # Session
        case "debug_connect":
            return await debugger.connect(
                host=args.get("host", "127.0.0.1"),
                port=args.get("port", 4711),
            )
        case "debug_launch":
            return await debugger.launch(
                program=args["program"],
                stop_on_entry=args.get("stop_on_entry", True),
                source_file=args.get("source_file"),
                map_file=args.get("map_file"),
                text_start=args.get("text_start"),
            )
        case "debug_attach":
            return await debugger.attach(
                source_file=args.get("source_file"),
                map_file=args.get("map_file"),
                stop=args.get("stop", True),
            )
        case "debug_disconnect":
            return await debugger.disconnect(terminate=args.get("terminate", True))
        case "debug_status":
            return await debugger.status()

        # Execution
        case "debug_continue":
            return await debugger.continue_execution(thread_id=args.get("thread_id", 1))
        case "debug_step_in":
            return await debugger.step_in(
                thread_id=args.get("thread_id", 1),
                granularity=args.get("granularity"),
            )
        case "debug_step_over":
            return await debugger.step_over(
                thread_id=args.get("thread_id", 1),
                granularity=args.get("granularity"),
            )
        case "debug_step_out":
            return await debugger.step_out(thread_id=args.get("thread_id", 1))
        case "debug_pause":
            return await debugger.pause(thread_id=args.get("thread_id", 1))

        # Breakpoints
        case "debug_set_breakpoints":
            return await debugger.set_breakpoints(
                source=args["source"],
                lines=args["lines"],
                conditions=args.get("conditions"),
            )
        case "debug_set_instruction_breakpoints":
            return await debugger.set_instruction_breakpoints(
                addresses=args["addresses"],
                conditions=args.get("conditions"),
            )
        case "debug_set_data_breakpoints":
            return await debugger.set_data_breakpoints(
                variables=args["variables"],
                access_type=args.get("access_type", "write"),
                address_space=args.get("address_space", "virtual"),
                conditions=args.get("conditions"),
            )
        case "debug_watch_register":
            return await debugger.watch_register(
                register=args["register"],
                condition=args.get("condition", ""),
            )
        case "debug_set_function_breakpoints":
            return await debugger.set_function_breakpoints(
                names=args["names"],
                conditions=args.get("conditions"),
            )

        # Inspection
        case "debug_stack_trace":
            return await debugger.stack_trace(thread_id=args.get("thread_id", 1))
        case "debug_variables":
            scope = args.get("scope")
            if isinstance(scope, str) and scope.isdigit():
                scope = int(scope)
            return await debugger.variables(
                scope=scope,
                frame_id=args.get("frame_id", 0),
                depth=args.get("depth", 1),
            )
        case "debug_evaluate":
            return await debugger.evaluate(
                expression=args["expression"],
                frame_id=args.get("frame_id", 0),
            )
        case "debug_add_watch":
            return await debugger.add_watch(expression=args["expression"])
        case "debug_remove_watch":
            return await debugger.remove_watch(index=args["index"])
        case "debug_clear_watches":
            return await debugger.clear_watches()
        case "debug_evaluate_watches":
            return await debugger.evaluate_watches(frame_id=args.get("frame_id", 0))
        case "debug_threads":
            return await debugger.threads()

        # Memory & Disassembly
        case "debug_read_memory":
            return await debugger.read_memory(
                address=args["address"],
                count=args.get("count", 256),
            )
        case "debug_write_memory":
            return await debugger.write_memory(
                address=args["address"],
                data=args["data"],
            )
        case "debug_disassemble":
            return await debugger.disassemble(
                address=args["address"],
                count=args.get("count", 20),
            )

        # Console I/O
        case "debug_console_enable":
            return await debugger.console_enable(
                terminal=args.get("terminal", 192),
                enable=args.get("enable", True),
            )
        case "debug_console_write":
            return await debugger.console_write(
                input=args["input"],
                terminal=args.get("terminal", 192),
            )
        case "debug_console_read":
            return await debugger.console_read(
                timeout=args.get("timeout", 2.0),
            )

        case "debug_symbol_list":
            return await debugger.symbol_list(
                filter=args.get("filter", ""),
                symbol_type=args.get("symbolType", 0),
                offset=args.get("offset", 0),
                count=args.get("count", 0),
            )

        # CPU execution tracing (RetroCore-custom)
        case "debug_set_cpu_tracing":
            return await debugger.set_cpu_tracing(
                enabled=args.get("enabled"),
                ring_capacity=args.get("ring_capacity"),
                pc_filter=args.get("pc_filter"),
            )
        case "debug_get_cpu_trace_ring":
            return await debugger.get_cpu_trace_ring(
                max_entries=args.get("max_entries", 0),
            )

        case _:
            return {"error": True, "message": f"Unknown tool: {name}"}


def main() -> None:
    """Entry point for the MCP DAP server."""
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    async def run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    asyncio.run(run())


if __name__ == "__main__":
    main()
