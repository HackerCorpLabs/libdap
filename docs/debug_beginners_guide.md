# 🐛 Debugging with DAP: A Friendly Beginner's Guide

Welcome to your new best friend in debugging: the **Debug Adapter Protocol (DAP)**. If you've ever wanted to feel like a wizard peeking inside a running program, DAP is your magic wand.

Whether you’re stepping through a function like a code ninja 🥷 or dissecting disassembly like a hardware hacker 🧠, this guide will take you from zero to hero.

---

## 🚀 What Even Is the Debug Adapter Protocol?

DAP is a protocol that lets editors and tools like VS Code talk to debuggers in a standardized way. Think of it as the universal translator between your code editor and the debugger.

It allows tools to:
- Start or attach to debug sessions
- Inspect threads, stack traces, and memory
- Set breakpoints and step through code
- Read/write memory and registers

---

## 🧰 Things You NEED to Know (Before You Rage Quit)

### 🛠 Starting a Debug Session
1. Start with `initialize` — like saying “Hello” to the debugger.
2. Use `launch` to start a program or `attach` to connect to one that's already running.

```json
{
  "command": "launch",
  "arguments": {
    "program": "./your_program",
    "stopOnEntry": true
  }
}
```

### 🔗 Attaching to a Running Program
```json
{
  "command": "attach",
  "arguments": {
    "processId": 1234
  }
}
```

### 🧵 Thread States You’ll Run Into
- `running`: Thread is doing stuff
- `stopped`: Thread is at a breakpoint or paused
- `terminated`: Thread is dead, Jim

---

## 🧠 Things You Didn’t Think You Needed to Know

### 📚 Stepping Types
- **next**: Step over
- **stepIn**: Step into a function
- **stepOut**: Finish current function and go up

### 🪤 Breakpoint Types
- Line, Function, Exception, Data, Conditional, Hit count, and more!

### 🧙 Memory and Register Access
Read/write memory with base64 data, inspect registers like `r0`, `pc`, `sp`. Do this only if you feel brave and want low-level insights.

---

## 🌟 Best Practices

### 🧵 Thread Management
- Always verify thread states before doing stuff.
- Use threadId `0` to affect ALL threads.

### 🐾 Stepping Smartly
- `next`: Step line by line
- `stepIn`: Dive deep
- `stepOut`: Escape quickly

### 🧠 Breakpoint Brilliance
- Clean up unused breakpoints.
- Use **conditions** to avoid constant triggering.
- Combine breakpoints with **log messages** or **hit counts** for loops.

### 📚 Format Tips
- Use `0x1234` for hex, `42` for decimal
- NEVER write `0123` unless you want octal
- Avoid negative hex like `-0x10` — use decimal instead (`-16`)

---

## 🧩 Common Questions

### 🤷‍♂️ Why doesn’t my thread stop?
- Wrong `threadId`?
- Is it even paused?
- Maybe it’s stuck in I/O or a syscall?

### 💥 Step doesn’t do anything?
- Make sure you’re stopped first.
- No source mapping? You might be in optimized code.

### 🕵️ Disassembly looks wrong?
- Check permissions or alignment.
- Are you reading a valid address?

---

## 🧠 Advanced Cool Stuff

### 🧨 Data Breakpoints
Trigger when memory at `0x1000` is written:
```json
{
  "command": "setDataBreakpoints",
  "arguments": {
    "breakpoints": [
      {
        "dataId": "0x1000",
        "accessType": "write",
        "condition": "value == 0xdeadbeef"
      }
    ]
  }
}
```

### 🗺 Source Mapping
Map memory address to source line:
```json
{
  "command": "disassemble",
  "arguments": {
    "source": {
      "path": "src/main.c",
      "line": 42
    }
  }
}
```

---

## 🧠 Debugging Tips You’ll Wish You Knew Sooner
- Always set `stopOnEntry` when launching new code.
- Add meaningful names to breakpoints.
- Read memory carefully — base64 decoding required!
- Keep your source map updated after every build.
- Test breakpoints in loops with `hitCondition` like `>5` or `%10`.

---

## ⚙️ Getting Started From Terminal
```bash
dap_debugger -h localhost -p 4711 your_program.bin -e -s ./src -m ./map.txt
```

---

## 💬 Final Words
Debugging can be fun when you know what you're doing. The DAP is powerful — it’s like a Swiss army knife for inspecting the guts of your code. Whether you're using it with VS Code or rolling your own client, this guide should get you going.

And remember:
> "Breakpoints are just breadcrumbs on your journey to understanding."

Happy debugging! 🧑‍💻

