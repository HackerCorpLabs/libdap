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
                    "map_file": {"type": "string", "description": "Path to .map file for source line mapping"},
                },
                "required": ["program"],
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
            name="debug_step_back",
            description="Step back to the previous execution point (requires reverse execution support).",
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
            description="Set data breakpoints (watchpoints) on variables.",
            inputSchema={
                "type": "object",
                "properties": {
                    "variables": {"type": "array", "items": {"type": "string"}, "description": "Variable names to watch"},
                    "access_type": {"type": "string", "enum": ["read", "write", "readWrite"], "default": "write"},
                },
                "required": ["variables"],
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
            name="debug_threads",
            description="Get list of threads.",
            inputSchema={"type": "object", "properties": {}},
        ),
        # Memory & Disassembly
        Tool(
            name="debug_read_memory",
            description="Read memory from the debuggee. Returns hex dump with ASCII representation.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Memory address (hex string like '0x1000')"},
                    "count": {"type": "integer", "default": 256, "description": "Number of bytes to read"},
                },
                "required": ["address"],
            },
        ),
        Tool(
            name="debug_write_memory",
            description="Write memory to the debuggee.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Memory address (hex string like '0x1000')"},
                    "data": {"type": "string", "description": "Hex string of bytes to write (e.g., '48454C4C4F')"},
                },
                "required": ["address", "data"],
            },
        ),
        Tool(
            name="debug_disassemble",
            description="Disassemble instructions at a memory address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Memory address (hex string like '0x1000')"},
                    "count": {"type": "integer", "default": 20, "description": "Number of instructions"},
                },
                "required": ["address"],
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
        case "debug_step_back":
            return await debugger.step_back(thread_id=args.get("thread_id", 1))
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
