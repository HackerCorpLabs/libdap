"""MCP tool implementations for DAP debugging."""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from . import types as fmt
from .dap_connection import DAPConnection

logger = logging.getLogger(__name__)


class DAPDebugger:
    """Stateful DAP debugger that persists across MCP tool calls."""

    def __init__(self) -> None:
        self.conn = DAPConnection()
        self.host: str = ""
        self.port: int = 0
        self.program: str = ""
        self.capabilities: dict[str, Any] = {}
        self.debugger_state: str = "disconnected"
        # Breakpoint state: source_path -> list of {line, condition?, hit_condition?, log_message?}
        self._source_breakpoints: dict[str, list[dict[str, Any]]] = {}
        # Instruction breakpoints: list of {address, condition?, hit_condition?}
        self._instruction_breakpoints: list[dict[str, Any]] = []

    def _check_connected(self) -> None:
        if not self.conn.connected:
            raise RuntimeError("Not connected to DAP server. Use debug_connect first.")

    def _check_response(self, response: dict[str, Any]) -> dict[str, Any]:
        if not response.get("success", False):
            return fmt.format_error(response)
        return response

    # ── Session Management ──────────────────────────────────────────────

    async def connect(self, host: str = "127.0.0.1", port: int = 4711) -> dict[str, Any]:
        """Connect to DAP server and initialize."""
        if self.conn.connected:
            await self.conn.disconnect()

        self.host = host
        self.port = port

        await self.conn.connect(host, port)

        # Send initialize
        response = await self.conn.send_request("initialize", {
            "clientID": "mcp-dap-debugger",
            "clientName": "MCP DAP Debugger",
            "adapterID": "nd100x",
            "pathFormat": "path",
            "linesStartAt1": True,
            "columnsStartAt1": True,
            "supportsVariableType": True,
            "supportsVariablePaging": True,
            "supportsRunInTerminalRequest": False,
            "supportsMemoryReferences": True,
            "supportsInvalidatedEvent": True,
        })

        err = self._check_response(response)
        if "error" in err:
            return err

        self.capabilities = response.get("body", {})
        self.debugger_state = "initialized"

        # Wait for initialized event
        event = await self.conn.wait_for_event({"initialized"}, timeout=5.0)
        logger.debug("Initialized event: %s", event.get("event"))

        return fmt.format_capabilities(response)

    async def launch(
        self, program: str, stop_on_entry: bool = True,
        source_file: str | None = None, map_file: str | None = None,
    ) -> dict[str, Any]:
        """Launch a program for debugging."""
        self._check_connected()

        args: dict[str, Any] = {
            "program": program,
            "stopOnEntry": stop_on_entry,
            "noDebug": False,
        }
        if source_file:
            args["sourceFile"] = source_file
        if map_file:
            args["mapFile"] = map_file

        response = await self.conn.send_request("launch", args)
        err = self._check_response(response)
        if "error" in err:
            return err

        self.program = program

        # Send configurationDone
        cfg_resp = await self.conn.send_request("configurationDone")
        self._check_response(cfg_resp)

        self.debugger_state = "running"

        # If stop_on_entry, wait for stopped event
        stopped_event = None
        if stop_on_entry:
            stopped_event = await self.conn.wait_for_event(
                {"stopped", "terminated", "exited"}, timeout=10.0
            )
            if stopped_event.get("event") == "stopped":
                self.debugger_state = "stopped"

        return fmt.format_launch_status(response, stopped_event)

    async def disconnect(self, terminate: bool = True) -> dict[str, Any]:
        """Disconnect from the DAP server."""
        if not self.conn.connected:
            return {"status": "already disconnected"}

        try:
            response = await self.conn.send_request("disconnect", {
                "restart": False,
                "terminateDebuggee": terminate,
            }, timeout=5.0)
        except Exception:
            pass

        await self.conn.disconnect()
        self.debugger_state = "disconnected"
        self._source_breakpoints.clear()
        self._instruction_breakpoints.clear()
        return {"status": "disconnected"}

    async def status(self) -> dict[str, Any]:
        """Get current debugger status."""
        result: dict[str, Any] = {
            "connected": self.conn.connected,
            "state": self.debugger_state,
            "host": self.host,
            "port": self.port,
            "program": self.program,
        }
        if self._source_breakpoints:
            result["source_breakpoints"] = {
                src: [{"line": bp["line"]} for bp in bps]
                for src, bps in self._source_breakpoints.items()
            }
        if self._instruction_breakpoints:
            result["instruction_breakpoints"] = [
                {"address": bp["address"]} for bp in self._instruction_breakpoints
            ]
        # Drain any buffered events
        events = await self.conn.drain_events() if self.conn.connected else []
        if events:
            result["pending_events"] = [
                {"event": e.get("event"), "body": e.get("body")}
                for e in events
            ]
        return result

    # ── Execution Control ───────────────────────────────────────────────

    async def _execute_and_wait(
        self, command: str, arguments: dict[str, Any] | None = None, timeout: float = 30.0
    ) -> dict[str, Any]:
        """Send an execution command and wait for stopped/terminated/exited event.

        Some DAP servers (like the mock) don't send a stopped event after
        step commands -- they just set internal state. We use a short initial
        wait, then try to query the server state if no event arrives.
        """
        self._check_connected()

        # Drain any stale events from prior commands
        await self.conn.drain_events()

        response = await self.conn.send_request(command, arguments)
        err = self._check_response(response)
        if "error" in err:
            return err

        self.debugger_state = "running"

        # Wait for stopped event. Use a shorter initial timeout for step
        # commands since some servers don't send stopped events for steps.
        is_step = command in ("next", "stepIn", "stepOut", "stepBack")
        initial_timeout = 2.0 if is_step else timeout

        event = await self.conn.wait_for_event(
            {"stopped", "terminated", "exited"}, timeout=initial_timeout
        )

        event_name = event.get("event", "timeout")
        if event_name == "stopped":
            self.debugger_state = "stopped"
            return fmt.format_stopped_event(event)
        elif event_name == "terminated":
            self.debugger_state = "terminated"
            return {"status": "terminated"}
        elif event_name == "exited":
            self.debugger_state = "exited"
            code = event.get("body", {}).get("exitCode")
            return {"status": "exited", "exit_code": code}
        elif is_step:
            # Server didn't send a stopped event but the step response was
            # successful -- assume we've stopped. Try to get current location
            # from a stack trace.
            self.debugger_state = "stopped"
            location = await self._get_current_location()
            return {
                "reason": "step",
                "thread_id": (arguments or {}).get("threadId", 1),
                **location,
            }
        else:
            # True timeout for continue/other commands
            return event.get("body", {"reason": "timeout"})

    async def _get_current_location(self) -> dict[str, Any]:
        """Try to get current stop location from stack trace."""
        try:
            response = await self.conn.send_request("stackTrace", {"threadId": 1}, timeout=3.0)
            if response.get("success"):
                frames = response.get("body", {}).get("stackFrames", [])
                if frames:
                    f = frames[0]
                    result: dict[str, Any] = {
                        "name": f.get("name", ""),
                        "line": f.get("line"),
                    }
                    if f.get("instructionPointerReference"):
                        result["instruction_pointer"] = f["instructionPointerReference"]
                    source = f.get("source")
                    if source:
                        result["source"] = source.get("path") or source.get("name", "")
                    return result
        except Exception:
            pass
        return {}

    async def continue_execution(self, thread_id: int = 1) -> dict[str, Any]:
        """Continue execution."""
        return await self._execute_and_wait("continue", {"threadId": thread_id})

    async def step_in(self, thread_id: int = 1, granularity: str | None = None) -> dict[str, Any]:
        """Step into."""
        args: dict[str, Any] = {"threadId": thread_id}
        if granularity:
            args["granularity"] = granularity
        return await self._execute_and_wait("stepIn", args)

    async def step_over(self, thread_id: int = 1, granularity: str | None = None) -> dict[str, Any]:
        """Step over (next)."""
        args: dict[str, Any] = {"threadId": thread_id}
        if granularity:
            args["granularity"] = granularity
        return await self._execute_and_wait("next", args)

    async def step_out(self, thread_id: int = 1) -> dict[str, Any]:
        """Step out."""
        return await self._execute_and_wait("stepOut", {"threadId": thread_id})

    async def step_back(self, thread_id: int = 1) -> dict[str, Any]:
        """Step back."""
        return await self._execute_and_wait("stepBack", {"threadId": thread_id})

    async def pause(self, thread_id: int = 1) -> dict[str, Any]:
        """Pause execution."""
        self._check_connected()
        response = await self.conn.send_request("pause", {"threadId": thread_id})
        err = self._check_response(response)
        if "error" in err:
            return err
        return {"status": "pause requested"}

    # ── Breakpoints ─────────────────────────────────────────────────────

    async def set_breakpoints(
        self,
        source: str,
        lines: list[int],
        conditions: list[str] | None = None,
    ) -> dict[str, Any]:
        """Set breakpoints for a source file (merges with existing)."""
        self._check_connected()

        # Merge with existing breakpoints for this source
        existing = {bp["line"]: bp for bp in self._source_breakpoints.get(source, [])}
        for i, line in enumerate(lines):
            bp: dict[str, Any] = {"line": line}
            if conditions and i < len(conditions) and conditions[i]:
                bp["condition"] = conditions[i]
            existing[line] = bp

        bp_list = list(existing.values())
        self._source_breakpoints[source] = bp_list

        # DAP setBreakpoints replaces all for this source
        dap_bps = []
        for bp in bp_list:
            entry: dict[str, Any] = {"line": bp["line"]}
            if bp.get("condition"):
                entry["condition"] = bp["condition"]
            if bp.get("hit_condition"):
                entry["hitCondition"] = bp["hit_condition"]
            if bp.get("log_message"):
                entry["logMessage"] = bp["log_message"]
            dap_bps.append(entry)

        response = await self.conn.send_request("setBreakpoints", {
            "source": {"path": source},
            "breakpoints": dap_bps,
        })
        err = self._check_response(response)
        if "error" in err:
            return err

        return {"source": source, "breakpoints": fmt.format_breakpoints(response)}

    async def set_instruction_breakpoints(
        self,
        addresses: list[str],
        conditions: list[str] | None = None,
    ) -> dict[str, Any]:
        """Set instruction breakpoints."""
        self._check_connected()

        # Merge with existing
        existing = {bp["address"]: bp for bp in self._instruction_breakpoints}
        for i, addr in enumerate(addresses):
            bp: dict[str, Any] = {"address": addr}
            if conditions and i < len(conditions) and conditions[i]:
                bp["condition"] = conditions[i]
            existing[addr] = bp

        self._instruction_breakpoints = list(existing.values())

        dap_bps = []
        for bp in self._instruction_breakpoints:
            entry: dict[str, Any] = {"instructionReference": bp["address"]}
            if bp.get("condition"):
                entry["condition"] = bp["condition"]
            if bp.get("hit_condition"):
                entry["hitCondition"] = bp["hit_condition"]
            dap_bps.append(entry)

        response = await self.conn.send_request("setInstructionBreakpoints", {
            "breakpoints": dap_bps,
        })
        err = self._check_response(response)
        if "error" in err:
            return err

        return {"breakpoints": fmt.format_breakpoints(response)}

    async def set_data_breakpoints(
        self,
        variables: list[str],
        access_type: str = "write",
        address_space: str = "virtual",
    ) -> dict[str, Any]:
        """Set data breakpoints (watchpoints)."""
        self._check_connected()

        # Prefix variables with address space hint for physical mode
        prefix = "phys:" if address_space == "physical" else ""

        # First get data breakpoint info for each variable
        dap_bps = []
        for var_name in variables:
            info_resp = await self.conn.send_request("dataBreakpointInfo", {
                "name": f"{prefix}{var_name}",
            })
            if not info_resp.get("success"):
                continue
            data_id = info_resp.get("body", {}).get("dataId")
            if data_id:
                dap_bps.append({
                    "dataId": data_id,
                    "accessType": access_type,
                })

        if not dap_bps:
            return {"error": True, "message": "No valid data breakpoints could be set"}

        response = await self.conn.send_request("setDataBreakpoints", {
            "breakpoints": dap_bps,
        })
        err = self._check_response(response)
        if "error" in err:
            return err

        return {"breakpoints": fmt.format_breakpoints(response)}

    async def set_function_breakpoints(
        self,
        names: list[str],
        conditions: list[str] | None = None,
    ) -> dict[str, Any]:
        """Set breakpoints on functions by name."""
        self._check_connected()

        dap_bps = []
        for i, name in enumerate(names):
            bp: dict[str, Any] = {"name": name}
            if conditions and i < len(conditions) and conditions[i]:
                bp["condition"] = conditions[i]
            dap_bps.append(bp)

        response = await self.conn.send_request("setFunctionBreakpoints", {
            "breakpoints": dap_bps,
        })
        err = self._check_response(response)
        if "error" in err:
            return err
        return {"breakpoints": fmt.format_breakpoints(response)}

    # ── Inspection ──────────────────────────────────────────────────────

    async def stack_trace(self, thread_id: int = 1) -> dict[str, Any]:
        """Get the call stack."""
        self._check_connected()
        response = await self.conn.send_request("stackTrace", {
            "threadId": thread_id,
        })
        err = self._check_response(response)
        if "error" in err:
            return err
        return {"frames": fmt.format_stack_trace(response)}

    async def threads(self) -> dict[str, Any]:
        """Get thread list."""
        self._check_connected()
        response = await self.conn.send_request("threads")
        err = self._check_response(response)
        if "error" in err:
            return err
        return {"threads": fmt.format_threads(response)}

    async def variables(
        self, scope: str | int | None = None, frame_id: int = 0, depth: int = 1
    ) -> dict[str, Any]:
        """Get variables. If scope is a string, look up the scope by name. If int, use as variables_reference directly."""
        self._check_connected()

        # Get scopes for the frame
        scopes_resp = await self.conn.send_request("scopes", {"frameId": frame_id})
        err = self._check_response(scopes_resp)
        if "error" in err:
            return err

        scopes_list = scopes_resp.get("body", {}).get("scopes", [])
        formatted_scopes = fmt.format_scopes(scopes_resp)

        # Determine which scope(s) to query
        var_refs: list[tuple[str, int]] = []
        if scope is None:
            # Return all scopes (skip empty ones with no name or ref=0)
            for i, s in enumerate(scopes_list):
                ref = s.get("variablesReference", 0)
                name = s.get("name")
                if ref > 0 and name:
                    var_refs.append((name, ref))
        elif isinstance(scope, int):
            var_refs.append(("scope", scope))
        else:
            # Find scope by name (case-insensitive)
            scope_lower = scope.lower()
            for i, s in enumerate(scopes_list):
                name = s.get("name", f"scope_{i}")
                if scope_lower in name.lower():
                    var_refs.append((name, s.get("variablesReference", 0)))
            if not var_refs:
                return {
                    "error": True,
                    "message": f"Scope '{scope}' not found",
                    "available_scopes": formatted_scopes,
                }

        # Fetch variables for each scope
        result: dict[str, Any] = {"scopes": {}}
        for scope_name, ref in var_refs:
            vars_list = await self._fetch_variables_recursive(ref, depth)
            result["scopes"][scope_name] = vars_list

        return result

    async def _fetch_variables_recursive(
        self, variables_reference: int, depth: int
    ) -> list[dict[str, Any]]:
        """Fetch variables, expanding children up to depth levels."""
        response = await self.conn.send_request("variables", {
            "variablesReference": variables_reference,
        })
        if not response.get("success"):
            return []

        raw_vars = response.get("body", {}).get("variables", [])
        formatted = fmt.format_variables(raw_vars)

        if depth > 1:
            for i, var in enumerate(raw_vars):
                child_ref = var.get("variablesReference", 0)
                if child_ref > 0:
                    children = await self._fetch_variables_recursive(child_ref, depth - 1)
                    formatted[i]["children"] = children

        return formatted

    async def evaluate(
        self, expression: str, frame_id: int = 0, context: str = "repl"
    ) -> dict[str, Any]:
        """Evaluate an expression."""
        self._check_connected()
        args: dict[str, Any] = {
            "expression": expression,
            "context": context,
        }
        if frame_id:
            args["frameId"] = frame_id

        response = await self.conn.send_request("evaluate", args)
        err = self._check_response(response)
        if "error" in err:
            return err
        return fmt.format_evaluate(response)

    # ── Memory & Disassembly ────────────────────────────────────────────

    async def read_memory(
        self, address: str, count: int = 256
    ) -> dict[str, Any]:
        """Read memory from the debuggee."""
        self._check_connected()
        response = await self.conn.send_request("readMemory", {
            "memoryReference": address,
            "count": count,
        })
        err = self._check_response(response)
        if "error" in err:
            return err
        return fmt.format_memory_read(response)

    async def write_memory(
        self, address: str, data: str
    ) -> dict[str, Any]:
        """Write memory to the debuggee. Data is hex string like '48454C4C4F'."""
        self._check_connected()
        # Convert hex string to base64
        try:
            raw = bytes.fromhex(data)
        except ValueError:
            return {"error": True, "message": "Invalid hex string for data"}

        b64 = base64.b64encode(raw).decode("ascii")
        response = await self.conn.send_request("writeMemory", {
            "memoryReference": address,
            "data": b64,
        })
        err = self._check_response(response)
        if "error" in err:
            return err
        return fmt.format_memory_write(response)

    async def disassemble(
        self, address: str, count: int = 20
    ) -> dict[str, Any]:
        """Disassemble instructions at address."""
        self._check_connected()
        response = await self.conn.send_request("disassemble", {
            "memoryReference": address,
            "instructionCount": count,
        })
        err = self._check_response(response)
        if "error" in err:
            return err
        return {"instructions": fmt.format_disassembly(response)}
