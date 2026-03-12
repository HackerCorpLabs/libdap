
# Minimal Debugger Experience - Required DAP Messages

This table lists the minimum set of Debug Adapter Protocol (DAP) messages required for a usable debugger, plus highly recommended additions for a better experience.

## ✅ Must-Have Messages

| **Category**        | **DAP Message**       | **Description**                                     |
|---------------------|------------------------|-----------------------------------------------------|
| Init & Launch       | `initialize`           | Sets up the client-server capabilities              |
|                     | `launch` or `attach`   | Starts or connects to the debug target              |
|                     | `configurationDone`    | Signals that configuration is complete              |
| Execution Control   | `continue`             | Resumes execution                                   |
|                     | `pause`                | Interrupts execution                                |
|                     | `next`                 | Steps over a line                                   |
|                     | `stepIn`               | Steps into a function                               |
|                     | `stepOut`              | Steps out of the current function                   |
| Breakpoints         | `setBreakpoints`       | Sets line breakpoints                               |
| Events              | `stopped`              | Indicates target is paused                          |
|                     | `terminated`           | Signals debuggee is terminating                     |
|                     | `exited`               | Signals the debuggee has exited                     |
|                     | `initialized`          | Signals debugger is ready for configuration         |
| Stack & Variables   | `stackTrace`           | Returns call stack                                  |
|                     | `scopes`               | Lists variable scopes at a stack frame              |
|                     | `variables`            | Gets variables in a scope                           |
| Threads             | `threads`              | Lists active threads                                |
| Source              | `source`               | Returns source code for a given source reference    |

## ➕ Recommended Next

| **Category**        | **DAP Message**       | **Description**                                     |
|---------------------|------------------------|-----------------------------------------------------|
| Evaluation          | `evaluate`             | Evaluates expressions (watch window, REPL)          |
|                     | `setVariable`          | Changes value of a variable                         |
| Output              | `output` (event)       | Sends stdout, stderr, and log output to client      |
