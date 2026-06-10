# dap-debugger (SDL3 / ImGui GUI)

A graphical DAP debugger client built on SDL3 + Dear ImGui (docking branch). It connects to any
DAP server (e.g. the RetroCore emulator on TCP 4711) and provides panels for source, registers
(Variables), stack, memory, disassembly, breakpoints/watchpoints, CPU tracing, and the raw
protocol log.

## Build

```
cmake -S . -B build
cmake --build build
./build/dap_gui_debugger
```

(SDL3 + ImGui are fetched by CMake; see `CMakeLists.txt`.)

## Register watchpoints (break on register change / value / bit)

The GUI lets you arm a **register watch** visually — no need to type a `reg:NAME` dataId or
remember the condition grammar. A register watch breaks when a CPU register changes, matches a
value, or has a specific bit flip. (Background: [../../docs/register-watchpoints.md](../../docs/register-watchpoints.md).)

### Entry points

- **Variables panel → right-click a register:**
  - **Break on change** — one click; arms an any-change watch on that register.
  - **Register watch…** — opens the visual dialog, pre-targeted at that register.
- **Breakpoints panel → Watchpoints tab → `+ Register watch…`** — opens the dialog with the
  register unselected (pick it from the dropdown).
- **Watchpoints tab → `E` button** on a register-watch row — re-opens the dialog pre-filled to
  edit that watch (edit = remove + re-add, since DAP has no in-place edit).

### The Register-Watch dialog

- **Register** — dropdown populated from the live `Registers` scope (no typing).
- **Mode** — *changes (any)* / *matches a value* / *has a bit condition*.
- **Value mode** — operator dropdown (`== != < > <= >=`), a value field, and an optional mask
  field. Accepts `0x` hex or decimal.
- **Bit mode** — a **clickable bit grid** laid out MSB→LSB, 8 bits per row, sized to the
  register's width (from its `N-bit` type). Set bits are highlighted green from the register's
  live value; the selected target bit is blue. Pick the bit, then choose `-> 1` (rises) /
  `-> 0` (falls) / `changed`.
- **Live preview** — shows exactly what will be armed, e.g. `reg:USP  bit 27 -> 1`.
- **Set / Update** sends it through the one submit path (`setDataBreakpoints`); **Cancel**
  discards.

### Watchpoints table

Lists all data breakpoints (memory + register), with a **Condition** column. Register rows show
a dash in the Address column (they have no numeric address). Each register row has **E** (edit)
and **X** (delete); **Clear All** removes everything.

### Worked example — "break when USP bit 27 becomes 1"

1. Connect to the DAP server and pause the CPU.
2. In the Variables panel, right-click `USP` → **Register watch…**.
3. Choose **has a bit condition**, click bit **27** in the grid, select **-> 1**.
4. The preview reads `reg:USP  bit 27 -> 1`. Click **Set**.
5. Continue — the debugger stops with reason `dataBreakpoint` when USP's bit 27 rises 0→1.
