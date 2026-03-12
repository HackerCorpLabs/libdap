"""Response formatting helpers for MCP tool results."""

from __future__ import annotations

import base64
from typing import Any


def _parse_address(addr: str) -> int:
    """Parse an address string that may be hex (0x...), octal (0o... or bare digits), or decimal."""
    addr = addr.strip()
    if not addr:
        return 0
    # Standard prefixed formats
    if addr.startswith(("0x", "0X", "0o", "0O", "0b", "0B")):
        return int(addr, 0)
    # Bare octal from ND-100 (all digits, often leading zeros, may contain 8/9 though)
    # If all chars are 0-7 and length >= 4, treat as octal
    if len(addr) >= 4 and all(c in "01234567" for c in addr):
        return int(addr, 8)
    # Otherwise try decimal
    try:
        return int(addr)
    except ValueError:
        return 0


def _decode_memory_data(data: str) -> bytes:
    """Decode memory data from DAP response.

    DAP spec says base64, but some servers (including the libdap mock)
    send hex-encoded strings instead. Detect and handle both.
    """
    if not data:
        return b""

    # Check if it looks like a hex string (only hex chars, even length)
    if len(data) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in data):
        try:
            return bytes.fromhex(data)
        except ValueError:
            pass

    # Otherwise try base64
    try:
        return base64.b64decode(data)
    except Exception:
        return b""


def format_capabilities(body: dict[str, Any]) -> dict[str, Any]:
    """Format initialize response capabilities."""
    return {
        "status": "connected",
        "capabilities": body.get("body", {}),
    }


def format_launch_status(response: dict[str, Any], event: dict[str, Any] | None = None) -> dict[str, Any]:
    """Format launch response."""
    result: dict[str, Any] = {
        "status": "launched",
        "success": response.get("success", False),
    }
    if event:
        result["stopped"] = format_stopped_event(event)
    return result


def format_stopped_event(event: dict[str, Any]) -> dict[str, Any]:
    """Format a stopped event into a readable dict."""
    body = event.get("body", {})
    result: dict[str, Any] = {
        "reason": body.get("reason", "unknown"),
        "thread_id": body.get("threadId"),
        "all_threads_stopped": body.get("allThreadsStopped"),
    }
    if body.get("description"):
        result["description"] = body["description"]
    if body.get("text"):
        result["text"] = body["text"]
    # Include buffered events if any
    buffered = event.get("buffered_events", [])
    if buffered:
        result["output"] = [
            format_output_event(e) for e in buffered if e.get("event") == "output"
        ]
    return result


def format_output_event(event: dict[str, Any]) -> dict[str, Any]:
    """Format an output event."""
    body = event.get("body", {})
    return {
        "category": body.get("category", "console"),
        "output": body.get("output", ""),
    }


def format_threads(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Format threads response."""
    threads = body.get("body", {}).get("threads", [])
    return [{"id": t["id"], "name": t.get("name", "")} for t in threads]


def format_stack_trace(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Format stack trace response."""
    frames = body.get("body", {}).get("stackFrames", [])
    result = []
    for f in frames:
        frame: dict[str, Any] = {
            "id": f["id"],
            "name": f.get("name", ""),
            "line": f.get("line"),
            "column": f.get("column"),
        }
        source = f.get("source")
        if source:
            frame["source"] = source.get("path") or source.get("name", "")
        if f.get("instructionPointerReference"):
            frame["instruction_pointer"] = f["instructionPointerReference"]
        if f.get("moduleId"):
            frame["module"] = f["moduleId"]
        result.append(frame)
    return result


def format_scopes(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Format scopes response. Filters out empty/uninitialized scopes."""
    scopes = body.get("body", {}).get("scopes", [])
    return [
        {
            "name": s.get("name", f"scope_{i}"),
            "variables_reference": s.get("variablesReference", 0),
            "expensive": s.get("expensive", False),
            "named_variables": s.get("namedVariables"),
            "indexed_variables": s.get("indexedVariables"),
        }
        for i, s in enumerate(scopes)
        if s.get("name") and s.get("variablesReference", 0) > 0
    ]


def format_variables(variables: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Format variables list."""
    result = []
    for i, v in enumerate(variables):
        var: dict[str, Any] = {
            "name": v.get("name", f"var_{i}"),
            "value": v.get("value", ""),
        }
        if v.get("type"):
            var["type"] = v["type"]
        if v.get("variablesReference", 0) > 0:
            var["variables_reference"] = v["variablesReference"]
            var["has_children"] = True
        if v.get("memoryReference"):
            var["memory_reference"] = v["memoryReference"]
        if v.get("evaluateName"):
            var["evaluate_name"] = v["evaluateName"]
        result.append(var)
    return result


def format_evaluate(body: dict[str, Any]) -> dict[str, Any]:
    """Format evaluate response."""
    b = body.get("body", {})
    result: dict[str, Any] = {
        "result": b.get("result", ""),
        "type": b.get("type", ""),
    }
    if b.get("variablesReference", 0) > 0:
        result["variables_reference"] = b["variablesReference"]
    if b.get("memoryReference"):
        result["memory_reference"] = b["memoryReference"]
    return result


def format_breakpoints(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Format breakpoints from setBreakpoints response."""
    bps = body.get("body", {}).get("breakpoints", [])
    result = []
    for bp in bps:
        entry: dict[str, Any] = {
            "id": bp.get("id"),
            "verified": bp.get("verified", False),
            "line": bp.get("line"),
        }
        if bp.get("message"):
            entry["message"] = bp["message"]
        if bp.get("source", {}).get("path"):
            entry["source"] = bp["source"]["path"]
        if bp.get("instructionReference"):
            entry["instruction_reference"] = bp["instructionReference"]
        result.append(entry)
    return result


def format_memory_read(body: dict[str, Any]) -> dict[str, Any]:
    """Format readMemory response with hex dump."""
    b = body.get("body", {})
    address = b.get("address", "0x0")
    data_b64 = b.get("data", "")
    unreadable = b.get("unreadableBytes", 0)

    raw = _decode_memory_data(data_b64)

    # Build hex dump
    hex_lines = []
    base_addr = _parse_address(address) if isinstance(address, str) else address
    for offset in range(0, len(raw), 16):
        chunk = raw[offset : offset + 16]
        hex_part = " ".join(f"{byte:02X}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        hex_lines.append(f"0x{base_addr + offset:04X}  {hex_part:<48s}  {ascii_part}")

    return {
        "address": address,
        "bytes_read": len(raw),
        "unreadable_bytes": unreadable,
        "hex_dump": hex_lines,
        "raw_base64": data_b64,
    }


def format_memory_write(body: dict[str, Any]) -> dict[str, Any]:
    """Format writeMemory response."""
    b = body.get("body", {})
    return {
        "bytes_written": b.get("bytesWritten", 0),
        "offset": b.get("offset", 0),
    }


def format_disassembly(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Format disassemble response."""
    instructions = body.get("body", {}).get("instructions", [])
    return [
        {
            "address": inst.get("address", ""),
            "instruction": inst.get("instruction", ""),
            "instruction_bytes": inst.get("instructionBytes", ""),
            "symbol": inst.get("symbol"),
            "line": inst.get("line"),
            "source": (inst.get("location") or {}).get("path"),
        }
        for inst in instructions
    ]


def format_error(response: dict[str, Any]) -> dict[str, Any]:
    """Format an error response."""
    msg = response.get("message", "Unknown error")
    body = response.get("body", {})
    error_obj = body.get("error", {})
    return {
        "error": True,
        "message": error_obj.get("format", msg) if error_obj else msg,
        "command": response.get("command", ""),
    }
