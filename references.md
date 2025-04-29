# Reference documentation for Microsoft Visual Studio Debug Adapter (DAP)

## pipe transport
https://code.visualstudio.com/docs/cpp/pipe-transport

## Using C++ and WSL in VS Code
https://code.visualstudio.com/docs/cpp/config-wsl

## Debugger extension
https://code.visualstudio.com/api/extension-guides/debugger-extension


## VSCode mock
https://github.com/microsoft/vscode-mock-debug


## Existing adapters
https://microsoft.github.io/debug-adapter-protocol/implementors/adapters/

Look at the existing C/C++ versions
* https://github.com/Microsoft/vscode-cpptools
* https://github.com/Marus/cortex-debug


## Mapping Assembly Lines to Code Addresses
To support breakpoints, stepping, and source-code-level debugging, VS Code needs a way to map source lines to executable memory addresses.

You'll need to:
 * Extend your ndas assembler to output source-to-address mapping data during compilation.

This could be:
 * A sidecar .map file: e.g., main.ndasm.map
 * Or embedded in a debug format (similar to DWARF or STABS, but you can define your own simpler version).

Each entry should contain:
    <filename>:<line_number> -> <address>

### Example .map format
main.ndasm:5 -> 000040
main.ndasm:6 -> 000042
Then in your emulator:

Maintain a structure that maps memory addresses to source lines (and vice versa) so that you can respond to DAP requests like setBreakpoints, stackTrace, and scopes.

In this version we will use an external .map file

## Key DAP Messages to Implement
Here's a minimal set of requests you should support to get basic source-level debugging:

* Initialization
  * initialize
  * launch or attach

* Source-level Debugging
  * setBreakpoints
  * configurationDone
  * threads (you can return one fake thread)
  * stackTrace (return current PC and mapped source line)
  * scopes and variables (for inspecting registers or memory)

* Execution Control
  * continue
  * next (step over)
  * stepIn, stepOut
  * pause

* Program Termination
  * disconnect
  * terminate


## Visual Studio Code Integration

You’ll also need a VS Code extension or launch.json config that launches your emulator + assembler.

Example launch.json:

{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "nd100x-dap",
      "request": "launch",
      "name": "Debug ND100x",
      "program": "${workspaceFolder}/main.ndasm",
      "dapServer": "tcp://127.0.0.1:12345"
    }
  ]
}




