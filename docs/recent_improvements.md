# Recent Improvements and New Features

This document outlines the major improvements and new features added to libDAP, transforming it from a basic DAP implementation into a professional-grade debugging toolkit.

## 2026-05 — Split I/D debugging, PIL-aware commands, watchpoint optimization

### Pause command fix

`debug_pause()` previously returned "Unknown error". The root cause was
twofold: libdap's `handle_pause` never invoked the emulator's pause
callback, and nd100x never registered one. Both are now fixed. Pause
reliably stops the CPU, and continue/step resumes normally.

### I-space / D-space address space support

When the kernel runs with split I/D (PTM=1), the same virtual address
maps to different physical memory for instruction fetch (I-space, via
the PT field of the PCR) vs data access (D-space, via the APT field).
The DAP disassembler previously read through the runtime MMS path which
could resolve to D-space, causing overlay code disassembly to show
garbage instead of actual instructions.

**Disassembler fix:** `cmd_disassemble` and all instruction-scanning
helpers now use `Dbg_ReadVirtualMemoryISpace()` which explicitly selects
the instruction page table from the PCR. No traps are generated and no
PGU/WIP bits are modified -- safe to call from debugger handlers without
disturbing CPU state.

**New address-space prefixes:** `readMemory`, `writeMemory`, and
`disassemble` now accept `ispace:` / `I:` (instruction page table) and
`dspace:` / `D:` (data page table) prefixes on `memoryReference`,
alongside the existing `phys:` / `P:` and `virt:` / `V:` prefixes.

The `DAPDataBreakpointAddressSpace` enum gained `DAP_DATA_BP_ADDR_ISPACE`
and `DAP_DATA_BP_ADDR_DSPACE` values. The C client, C++ debugger client,
ImGui Memory panel, and MCP tool descriptions have been updated.

### @PIL suffix for cross-level inspection

All memory commands (`readMemory`, `writeMemory`, `disassemble`) now
accept an optional `@N` suffix (N=0-15) on the `memoryReference` string
to read/write/disassemble using a specific PIL's page table instead of
the current one. This is essential for inspecting user process memory
(PIL 1) while stopped in the kernel (PIL 0 or 14).

Address encoding: `[prefix:]address[@pil]`

Examples:
- `"0x1000@1"` -- virtual, using PIL 1's page table
- `"ispace:0xBA60@0"` -- I-space, using PIL 0's page table
- `"dspace:0x100@1"` -- D-space, using PIL 1's page table
- `"phys:0x10000"` -- physical (PIL ignored, no MMU)

Omitting `@N` uses the current PIL (backward compatible).

### UseAPT-aware watchpoints with PIL filtering

Data watchpoints (`setDataBreakpoints`) now support I-space/D-space
filtering and optional PIL restriction via the `dataId` string:

- Prefix `I:` -- watchpoint fires only on I-space access (UseAPT=false)
- Prefix `D:` -- watchpoint fires only on D-space access (UseAPT=true)
- Suffix `@N` -- watchpoint fires only when CPU is at PIL N
- Both are optional; defaults match all spaces and all PILs

DataId format: `PREFIX:OCTAL_ADDR[@PIL]`

Examples:
- `"I:135140"` -- I-space overlay code, any PIL
- `"D:135140@0"` -- D-space data, PIL 0 only
- `"P:010000@14"` -- physical address, PIL 14 only
- `"V:001000"` -- virtual, any space, any PIL (backward compatible)

### Watchpoint bitmap hot-path optimization

Virtual watchpoints now use an 8KB bitmap (1 bit per 16-bit address)
for O(1) fast rejection in the CPU memory access hot path. Performance:

| Scenario | Cost per memory access |
|----------|----------------------|
| No watchpoints set | 1 int compare (branch predictor: always not-taken) |
| Watchpoints active, address miss | + 1 byte load + 1 bit test |
| Watchpoints active, address HIT | + slow path with PIL/space/type checks |

The bitmap and counter are extern globals accessed directly from the
CPU loop -- no function call overhead. The 8KB bitmap fits in L1 cache.

## 2026-04 — Address-space-aware memory access

`readMemory` and `writeMemory` now accept an optional address-space prefix
on `memoryReference` (`phys:`, `P:`, `virt:`, `V:`). The parsed value is
exposed to integrators via a new `address_space` field on
`ReadMemoryCommandContext` and `WriteMemoryCommandContext`. The C client
gained `dap_client_read_memory_ex()` / `dap_client_write_memory_ex()`
that take a `DAPDataBreakpointAddressSpace` argument and emit the prefix
automatically. The GUI debugger (`tools/dap-debugger`) ships a new
**Memory** panel with a Virtual/Physical/I-space/D-space radio toggle
and hex view.

This unblocks debugging of split I/D (0411) kernels on the ND-100, where
data segments live above 64K of physical memory and cannot be reached
through the current page table. The mock server has been extended with
two distinct memory regions and an end-to-end test
(`test_address_space.py`) that verifies prefixes round-trip correctly.

The CPU memory hot path in nd100x is unchanged; the new debugger
accessors (`Dbg_ReadPhysicalMemory`, `Dbg_ReadVirtualMemoryISpace`,
`Dbg_ReadVirtualMemoryDSpace`, etc.) are only invoked from the DAP
command handler, so when no watchpoints are active there is zero added
cost per memory access.

## 🎯 Major Achievements

### 1. **Advanced Threading Architecture** ✅

**Implementation**: Complete separation of UI and DAP communication into dedicated threads

**Benefits**:
- Responsive user interface with real-time input handling
- Non-blocking DAP operations
- Thread-safe communication using pthread primitives
- Event-driven architecture with proper synchronization

**Technical Details**:
- `dap_client_thread.c`: Handles all DAP protocol communication
- `dap_ui_thread.c`: Manages user input and display with character-by-character processing
- `dap_debugger_threads.c`: Thread management and inter-thread communication
- Thread-safe circular buffer queues for commands and events
- Event notification using eventfd for efficient signaling

### 2. **Professional Memory Examination Tools** ✅

**Implementation**: Industry-standard hex dump functionality with base64 decoding

**Features**:
- Multiple command aliases: `x`, `memory`, `readMemory`
- Flexible parameter handling: address/symbol, byte count, offset
- Professional hex dump format with proper alignment
- Base64 decoding for DAP protocol compatibility
- ASCII representation alongside hex values

**Example Usage**:
```bash
dap# x 0x401000 64          # Examine 64 bytes at address
dap# memory main 32         # Examine 32 bytes at symbol 'main'
dap# readMemory 0x1000 16 8 # 16 bytes at offset 8
```

**Output Format**:
```
Memory Dump:
Address: 401000 (64 bytes)

Address  | 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f | ASCII
---------|--------------------------------------------------|----------------
00401000 | 48 89 e5 48 83 ec 20 89 7d fc c7 45 f8 00 00 00 | H..H.. .}..E....
00401010 | 00 8b 45 f8 83 c0 01 89 45 f8 83 7d f8 0a 7e ef | ..E.....E..}..~.
```

### 3. **Smart Parameter Validation and Caching** ✅

**Implementation**: Intelligent command validation with contextual caching

**Features**:
- Parameter validation with helpful error messages
- Smart caching of thread IDs, frame IDs, and variable references
- Auto-parameter filling using cached values
- Clear guidance on command usage and parameter requirements

**Smart Workflow**:
```bash
dap# threads              # Caches first thread ID
dap# stackTrace           # Uses cached thread ID automatically
dap# scopes               # Uses cached frame ID from stackTrace
dap# variables            # Uses cached variables reference from scopes
```

**Error Handling**:
```bash
dap# variables
Error: variables command requires a variables reference (get from scopes)

dap# scopes
Error: scopes command requires a frame ID (get from stackTrace)
```

### 4. **Beautiful Unicode Table Formatting** ✅

**Implementation**: Professional table output with dynamic column sizing

**Features**:
- Unicode box-drawing characters for clean table borders
- Dynamic column width calculation based on content and headers
- Proper alignment for both headers and data
- Flexible formatting system supporting multiple data types

**Table Examples**:
```
Threads:
┌────┬─────────────────┬─────────┐
│ ID │ Name            │ State   │
├────┼─────────────────┼─────────┤
│  1 │ Main Thread     │ stopped │
│  2 │ Worker Thread   │ running │
└────┴─────────────────┴─────────┘
```

### 5. **Comprehensive Command Set** ✅

**Implementation**: Full DAP protocol command support with validation

**Available Commands**:
- **Execution Control**: `continue`, `stepIn`, `stepOut`, `next`, `pause`
- **Program Control**: `launch`, `attach`, `detach`, `kill`, `restart`
- **Breakpoints**: `setBreakpoints`, `setExceptionBreakpoints`
- **Inspection**: `threads`, `stackTrace`, `scopes`, `variables`, `evaluate`
- **Memory**: `readMemory`, `disassemble`
- **Source**: `source` (code listing)
- **Utility**: `help`, `debugmode`, `exit`

**Command Aliases**: Each command has intuitive short aliases (e.g., `s` for step, `c` for continue, `x` for memory examine)

## 🔧 Technical Improvements

### Thread-Safe Architecture

- **Mutex Protection**: All shared state protected by pthread mutexes
- **Event-Driven Communication**: Non-blocking event queues with proper signaling
- **Resource Management**: Automatic cleanup and proper thread termination
- **State Synchronization**: Consistent state management across threads

### Error Handling and Recovery

- **Graceful Degradation**: Commands continue working even with partial failures
- **User-Friendly Messages**: Clear error descriptions with actionable guidance
- **Input Validation**: Comprehensive parameter checking before DAP requests
- **Memory Safety**: Buffer overflow protection and bounds checking

### Performance Optimizations

- **Non-Blocking Operations**: UI remains responsive during DAP operations
- **Efficient Parsing**: Optimized command parsing and argument handling
- **Memory Pooling**: Reusable formatters and data structures
- **Event Coalescing**: Efficient event processing to avoid UI flooding

## 🎨 User Experience Enhancements

### Responsive Interface

- **Real-Time Input**: Character-by-character input processing
- **Immediate Feedback**: Instant response to user actions
- **Progressive Display**: Results appear as soon as available
- **Interrupt Handling**: Proper Ctrl+C and exit handling

### Smart Workflows

- **Command Chaining**: Results from one command automatically feed into the next
- **Context Awareness**: Commands understand their execution context
- **Auto-Completion**: Intelligent parameter defaults based on previous commands
- **Help Integration**: Comprehensive help system with examples

### Professional Output

- **Consistent Formatting**: All output follows professional standards
- **Visual Hierarchy**: Clear separation between different types of information
- **Color Support**: Ready for terminal color enhancement
- **Accessibility**: Clear, readable output format

## 📊 Before and After Comparison

### Before
- Single-threaded blocking architecture
- Raw JSON output for all responses
- Basic command handling without validation
- Limited error messages
- Simple text-based formatting

### After
- Multi-threaded non-blocking architecture
- Professional table formatting with Unicode
- Smart parameter validation and caching
- Comprehensive error handling with guidance
- Industry-standard hex dump tools
- Beautiful, readable output for all data types

## 🚀 Impact

These improvements transform libDAP from a basic protocol implementation into a professional debugging toolkit that:

1. **Provides Professional User Experience**: Comparable to commercial debuggers
2. **Offers Complete Debugging Capabilities**: Memory examination, variable inspection, execution control
3. **Ensures Reliable Operation**: Thread-safe, error-resistant architecture
4. **Enables Productive Workflows**: Smart caching and validation reduce friction
5. **Supports Advanced Use Cases**: Professional memory analysis and debugging

The enhanced libDAP now serves as both an excellent example of DAP protocol implementation and a powerful debugging tool in its own right.