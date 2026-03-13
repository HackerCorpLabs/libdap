# Console I/O - DAP Protocol Extension

This document describes the custom DAP protocol extensions for terminal console I/O. These are not part of the standard Debug Adapter Protocol specification; they are custom requests implemented by libdap for use with CPU emulators that have terminal devices.

## Overview

The console I/O extension adds two custom DAP requests and uses the standard DAP `output` event:

| Component | Direction | Description |
|-----------|-----------|-------------|
| `consoleEnable` request | Client -> Server | Enable/disable terminal output capture |
| `consoleWrite` request | Client -> Server | Send keyboard input to terminal |
| `output` event (stdout) | Server -> Client | Captured terminal output character |

## Architecture

```
  MCP/Client                  DAP Server                    CPU Emulator
  ----------                  ----------                    ------------
  consoleEnable  -------->  Hook terminal output   ------> Replace outputFunc callback
                            callback on device

  consoleWrite   -------->  Queue keyboard input   ------> Terminal_QueueKeyCode()
                            to terminal device

                 <--------  output event           <------ outputFunc fires when
                            (category: stdout)             CPU writes to terminal
```

## Requests

### `consoleEnable`

Enable or disable console output capture on a terminal device. When enabled, characters written by the CPU to the terminal are intercepted and sent as DAP `output` events. The original terminal output callback is preserved and still called, so the terminal continues to function normally.

**Request:**
```json
{
  "command": "consoleEnable",
  "arguments": {
    "terminal": 192,
    "enable": true
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `terminal` | integer | 192 | IOX base address of the terminal device (decimal). Default 192 = octal 0300 = system console |
| `enable` | boolean | true | `true` to start capture, `false` to stop and restore original callback |

**Response:**
```json
{
  "success": true,
  "body": {
    "success": true,
    "terminal": 192,
    "enabled": true
  }
}
```

**Behavior:**
- On enable: saves the terminal's current `outputFunc` callback, replaces it with an interceptor that sends output events and then calls the original
- On disable: restores the original `outputFunc` callback
- Multiple terminals can be captured simultaneously (up to 8)
- Enabling an already-enabled terminal is a no-op
- If the terminal device is not found, the request fails

### `consoleWrite`

Send keyboard input to a terminal device. Each character is queued into the terminal's input buffer as if typed on a physical keyboard. The CPU reads these characters via IOX instructions.

**Request:**
```json
{
  "command": "consoleWrite",
  "arguments": {
    "terminal": 192,
    "input": "hello\r",
    "hex": false
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `terminal` | integer | 192 | IOX base address (decimal) |
| `input` | string | (required) | Characters to send. In text mode, standard JSON escapes apply. In hex mode, pairs of hex digits |
| `hex` | boolean | false | If `true`, `input` is interpreted as hex-encoded bytes |

**Response:**
```json
{
  "success": true,
  "body": {
    "success": true
  }
}
```

**Text mode** (`hex: false`):
- Characters are sent as-is through `Terminal_QueueKeyCode()`
- JSON string escapes work normally: `\r` = CR (Enter), `\n` = LF, `\t` = Tab
- Unicode escapes for control characters: `\u0003` = Ctrl-C, `\u001b` = ESC

**Hex mode** (`hex: true`):
- `input` contains pairs of hexadecimal digits, each pair representing one byte
- Example: `"1B5B41"` sends three bytes: 0x1B (ESC), 0x5B (`[`), 0x41 (`A`) -- the ANSI escape for arrow up
- Allows sending any byte value 0x00-0xFF

## Events

### `output` event (console capture)

When console capture is enabled and the CPU writes a character to the terminal, an `output` event is sent with `category: "stdout"`.

```json
{
  "type": "event",
  "event": "output",
  "body": {
    "category": "stdout",
    "output": "H",
    "data": "{\"terminal\":192,\"hex\":\"48\"}"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `category` | string | Always `"stdout"` for console capture events |
| `output` | string | The character as printable text. Non-printable characters (except CR, LF, Tab) are replaced with `.` |
| `data` | string | JSON-encoded string containing `terminal` (IOX address) and `hex` (two-digit hex of the raw byte value) |

The `data` field is a JSON string (not a JSON object) because the DAP `output` event's `data` field is typed as `any` in the spec. It contains:
- `terminal`: integer IOX base address identifying which terminal produced the output
- `hex`: two-character hex string of the exact byte value, preserving control characters and escape sequences that would be lost in the `output` text field

**One event per character**: Each character written by the CPU generates a separate output event. Clients should buffer events and periodically read the accumulated output rather than processing individual character events.

## Terminal Address Reference

The ND-100 uses IOX (I/O Exchange) addresses for device access. Terminal addresses are octal values converted to decimal for the JSON protocol:

| Terminal | Octal IOX | Decimal | Identity Code |
|----------|-----------|---------|---------------|
| Console  | 0300      | 192     | 01            |
| Terminal 5 | 0340    | 224     | 01            |

## Implementation Notes

### Server-side (libdap)

New command types in `dap_protocol.h`:
```c
DAP_CMD_CONSOLE_ENABLE,      // consoleEnable request
DAP_CMD_CONSOLE_WRITE,       // consoleWrite request
```

Context structs in `dap_server.h`:
```c
typedef struct {
    int terminal;       // IOX base address (decimal)
    bool enable;        // true=enable, false=disable
} ConsoleEnableContext;

typedef struct {
    int terminal;       // IOX base address (decimal)
    char *input;        // String to send
    bool hex;           // true=hex-encoded bytes
} ConsoleWriteContext;
```

Protocol handlers parse JSON arguments into these contexts, then call the registered implementation callback. The integrator (e.g., nd100x debugger) provides the actual implementation that hooks into the emulator's terminal device system.

### Client-side (libdap)

```c
int dap_client_console_enable(DAPClient* client, int terminal, bool enable);
int dap_client_console_write(DAPClient* client, int terminal, const char* input, bool hex);
```

### MCP layer

The MCP server provides three tools:
- `debug_console_enable` - wraps `consoleEnable` request
- `debug_console_write` - wraps `consoleWrite` request with text/hex mode auto-detection
- `debug_console_read` - drains buffered `output` events and returns accumulated text + hex

The `debug_console_read` tool has no corresponding DAP request; it operates entirely within the MCP server by collecting `output` events from the DAP event queue.
