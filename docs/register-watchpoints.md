# Register Watchpoints

Break when a CPU **register** changes, matches a value, or has a specific **bit** flip —
the register equivalent of a memory watchpoint. Implemented across the DAP server (the
RetroCore emulator), the libdap C library + CLI, and the SDL/ImGui GUI.

## How it rides on DAP

DAP has no native register-watch request. Register watches reuse the standard
`dataBreakpointInfo` / `setDataBreakpoints` flow, discriminated by a **dataId prefix**:

1. `dataBreakpointInfo` with a register `name` (e.g. `USP`) → the server returns the dataId
   **`reg:USP`** (instead of a memory-address dataId). This is spec-legitimate: registers are
   DAP *variables*, and `dataBreakpointInfo` is the blessed way to mint a dataId for a variable.
2. `setDataBreakpoints` carries **one mixed `breakpoints[]` array**. The server routes each
   entry by dataId: `reg:` → a CPU register watch; anything else → a memory watchpoint.

Because `setDataBreakpoints` is "replace the entire set", a single call must include **both**
the memory watches and the register watches you want to keep — the server clears both and
re-arms from the request. The client cache (`client->data_breakpoints[]`) holds both kinds
together for exactly this reason.

## Condition grammar (parsed server-side — single source of truth)

The CLI and GUI never parse conditions; they pass the string through and the DAP server parses
it. Forms:

| Condition          | Meaning                                                      |
|--------------------|-------------------------------------------------------------|
| *(empty)*          | break on any change to the register                         |
| `== 0x50000204`    | value equals (also `!=`, `<`, `>`, `<=`, `>=`)              |
| `& 0xFF == 0x42`   | masked value match                                          |
| `bit 27 -> 1`      | bit 27 goes 0→1 (also `set`)                                |
| `bit 27 -> 0`      | bit 27 goes 1→0 (also `clear`)                              |
| `bit 27 changed`   | either edge of bit 27 (also bare `bit 27`)                  |

Value-match fires on the **edge into** the matching state (it won't re-fire while the condition
stays true). The baseline is primed when the watch is armed, so a change on the first executed
instruction is caught. Firing produces a `stopped` event with reason `dataBreakpoint`.

## CLI usage (`dap_debugger`)

```
watch reg:USP                  # break on any change to USP
watch reg:USP == 0x50000204    # break when USP equals a value
watch reg:USP bit 27 -> 1      # break when USP bit 27 goes 0->1
watch reg:USP bit 27 changed   # break when USP bit 27 toggles
info watchpoints               # list watchpoints, including their conditions
```

`watch` re-sends the full set (existing + new) on each invocation; conditions on previously-set
watchpoints are preserved.

## Library note — condition persistence

The DAP server's `setDataBreakpoints` *response* does not echo the `condition` back. Because the
client rebuilds its cache from the response and re-sends the full set on the next call, the
client must persist the request's condition itself or it would be silently dropped on re-issue.
`dap_client.c` does this (copies the request `condition` into `client->data_breakpoints[]` after
a successful set), and `dap_client_clear_data_breakpoints` frees it.

## GUI

See the SDL/ImGui debugger — `tools/dap-debugger/README.md`, "Register watchpoints": a visual
dialog with a register dropdown, a clickable bit grid that reflects the register's live value,
a value/operator/mask editor, and a live preview of the exact `reg:NAME` + condition that will
be armed.
