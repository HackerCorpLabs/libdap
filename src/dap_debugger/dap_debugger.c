#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include "dap_debugger_types.h"
#include "dap_debugger_commands.h"


// Define the command table
const DebuggerCommand commands[] = {
    {
        .name = "help",
        .alias = "h",
        .syntax = "help [command]",
        .description = "Show help information for commands",
        .request_format = NULL,
        .response_format = NULL,
        .events = NULL,
        .has_options = true,
        .option_types = "command",
        .option_descriptions = "Command to show help for",
        .examples = "help|Show all commands|help break|Show help for break command",
        .category = CATEGORY_OTHER,
        .implemented = true,
        .handler = handle_help_command
    },
    {
        .name = "quit",
        .alias = "q",
        .syntax = "quit",
        .description = "Exit the debugger",
        .request_format = NULL,
        .response_format = NULL,
        .events = NULL,
        .has_options = false,
        .option_types = NULL,
        .option_descriptions = NULL,
        .examples = "quit|Exit the debugger",
        .category = CATEGORY_OTHER,
        .implemented = true,
        .handler = handle_quit_command
    },
    {
        .name = "continue",
        .alias = "c",
        .syntax = "continue [thread_id]",
        .description = "Continue execution",
        .request_format = "{\"threadId\": number, \"singleThread\": boolean}",
        .response_format = "{\"allThreadsContinued\": boolean}",
        .events = "continued",
        .has_options = true,
        .option_types = "thread_id",
        .option_descriptions = "Optional thread ID to continue",
        .examples = "continue|Continue all threads|continue 1|Continue thread 1",
        .category = CATEGORY_EXECUTION_CONTROL,
        .implemented = true,
        .handler = handle_continue_command
    },
    {
        .name = "next",
        .alias = "n",
        .syntax = "next [thread_id]",
        .description = "Step over next line",
        .request_format = "{\"threadId\": number, \"singleThread\": boolean}",
        .response_format = "{\"allThreadsContinued\": boolean}",
        .events = "continued",
        .has_options = true,
        .option_types = "thread_id",
        .option_descriptions = "Optional thread ID to step",
        .examples = "next|Step over in current thread|next 1|Step over in thread 1",
        .category = CATEGORY_EXECUTION_CONTROL,
        .implemented = true,
        .handler = handle_next_command
    },
    {
        .name = "step",
        .alias = "s",
        .syntax = "step [thread_id]",
        .description = "Step into function call",
        .request_format = "{\"threadId\": number, \"singleThread\": boolean}",
        .response_format = "{\"allThreadsContinued\": boolean}",
        .events = "continued",
        .has_options = true,
        .option_types = "thread_id",
        .option_descriptions = "Optional thread ID to step",
        .examples = "step|Step into in current thread|step 1|Step into in thread 1",
        .category = CATEGORY_EXECUTION_CONTROL,
        .implemented = true,
        .handler = handle_step_command
    },
    {
        .name = "step-out",
        .alias = "o",
        .syntax = "step-out [thread_id]",
        .description = "Step out of current function",
        .request_format = "{\"threadId\": number, \"singleThread\": boolean}",
        .response_format = "{\"allThreadsContinued\": boolean}",
        .events = "continued",
        .has_options = true,
        .option_types = "thread_id",
        .option_descriptions = "Optional thread ID to step",
        .examples = "step-out|Step out in current thread|step-out 1|Step out in thread 1",
        .category = CATEGORY_EXECUTION_CONTROL,
        .implemented = true,
        .handler = handle_step_out_command
    },
    {
        .name = "break",
        .alias = "b",
        .syntax = "break <line> [file]",
        .description = "Set a breakpoint",
        .request_format = "{\"source\": {\"path\": string}, \"breakpoints\": [{\"line\": number}]}",
        .response_format = "{\"breakpoints\": [{\"verified\": boolean, \"line\": number}]}",
        .events = "breakpoint",
        .has_options = true,
        .option_types = "line|file",
        .option_descriptions = "Line number|Optional file path",
        .examples = "break 42|Set breakpoint at line 42 in current file|break 42 main.c|Set breakpoint at line 42 in main.c",
        .category = CATEGORY_BREAKPOINTS,
        .implemented = true,
        .handler = handle_break_command
    },
    {
        .name = "exception",
        .alias = "ex",
        .syntax = "exception [filters]",
        .description = "Set exception breakpoints",
        .request_format = "{\"filters\": [string], \"filterOptions\": [{\"filterId\": string, \"condition\": string}]}",
        .response_format = "{\"breakpoints\": [{\"verified\": boolean, \"id\": number, \"message\": string}]}",
        .events = "stopped (reason: exception)",
        .has_options = true,
        .option_types = "all|uncaught|custom",
        .option_descriptions = "Break on all exceptions|Break on uncaught exceptions|Custom exception filter names",
        .examples = "exception|Set default exception breakpoint (uncaught)|exception all|Break on all exceptions|exception all,uncaught|Break on all and uncaught exceptions",
        .category = CATEGORY_BREAKPOINTS,
        .implemented = true,
        .handler = handle_exception_command
    },
    {
        .name = "info",
        .alias = "i",
        .syntax = "info [breakpoints|threads|registers|frame]",
        .description = "Show information about debuggee",
        .request_format = "Varies by subcommand",
        .response_format = "Varies by subcommand",
        .events = NULL,
        .has_options = true,
        .option_types = "breakpoints|threads|registers|frame",
        .option_descriptions = "List breakpoints|List threads|Show registers|Show current frame",
        .examples = "info breakpoints|List all breakpoints|info threads|List all threads",
        .category = CATEGORY_OTHER,
        .implemented = true,
        .handler = handle_info_command
    },
    {
        .name = "list",
        .alias = "l",
        .syntax = "list [file]",
        .description = "List source code",
        .request_format = "{\"source\": {\"path\": string}}",
        .response_format = "{\"content\": string}",
        .events = NULL,
        .has_options = true,
        .option_types = "file",
        .option_descriptions = "Optional file path to list",
        .examples = "list|List current file|list file.c|List file.c",
        .category = CATEGORY_SOURCE,
        .implemented = true,
        .handler = handle_list_command
    },
    {
        .name = "backtrace",
        .alias = "bt",
        .syntax = "backtrace [thread_id]",
        .description = "Show stack trace",
        .request_format = "{\"threadId\": number}",
        .response_format = "{\"stackFrames\": [{\"id\": number, \"name\": string, \"line\": number, \"column\": number}]}",
        .events = NULL,
        .has_options = true,
        .option_types = "thread_id",
        .option_descriptions = "Optional thread ID",
        .examples = "backtrace|Show stack trace for current thread|backtrace 1|Show stack trace for thread 1",
        .category = CATEGORY_STACK_AND_VARIABLES,
        .implemented = true,
        .handler = handle_backtrace_command
    },
    {
        .name = "variables",
        .alias = "v",
        .syntax = "variables [reference [depth]]",
        .description = "Show variables with hierarchical display and type information",
        .request_format = "{\"variablesReference\": number}",
        .response_format = "{\"variables\": [{\"name\": string, \"value\": string, \"type\": string, \"variablesReference\": number}]}",
        .events = NULL,
        .has_options = true,
        .option_types = "reference|depth",
        .option_descriptions = "Optional variables reference|Optional maximum recursion depth (default: 1)",
        .examples = "variables|Show all variables in all scopes|variables 1001|Show variables for reference 1001|variables 1001 2|Show variables for reference 1001 with maximum depth of 2",
        .category = CATEGORY_STACK_AND_VARIABLES,
        .implemented = true,
        .handler = handle_variables_command
    },
    {
        .name = "threads",
        .alias = "t",
        .syntax = "threads",
        .description = "List threads",
        .request_format = "{}",
        .response_format = "{\"threads\": [{\"id\": number, \"name\": string}]}",
        .events = NULL,
        .has_options = false,
        .option_types = NULL,
        .option_descriptions = NULL,
        .examples = "threads|List all threads",
        .category = CATEGORY_THREADS,
        .implemented = true,
        .handler = handle_threads_command
    },
    {
        .name = "scopes",
        .alias = "s",
        .syntax = "scopes [frame_id]",
        .description = "Show scopes for frame",
        .request_format = "{\"frameId\": number}",
        .response_format = "{\"scopes\": [{\"name\": string, \"variablesReference\": number}]}",
        .events = NULL,
        .has_options = true,
        .option_types = "frame_id",
        .option_descriptions = "Optional frame ID",
        .examples = "scopes|Show scopes for current frame|scopes 1|Show scopes for frame 1",
        .category = CATEGORY_STACK_AND_VARIABLES,
        .implemented = true,
        .handler = handle_scopes_command
    },
    {
        .name = "debugmode",
        .alias = "dm",
        .syntax = "debugmode [on|off]",
        .description = "Toggle debug mode",
        .request_format = NULL,
        .response_format = NULL,
        .events = NULL,
        .has_options = true,
        .option_types = "on|off",
        .option_descriptions = "Enable or disable debug mode",
        .examples = "debugmode|Toggle debug mode|debugmode on|Enable debug mode|debugmode off|Disable debug mode",
        .category = CATEGORY_OTHER,
        .implemented = true,
        .handler = handle_debugmode_command
    },
    {
        .name = "disassemble",
        .alias = "da",
        .syntax = "disassemble <memory_reference> [-o offset] [-i instruction_offset] [-c count] [-s]",
        .description = "Disassemble code at memory location",
        .request_format = "{\"memoryReference\": string, \"offset\": number, \"instructionOffset\": number, \"instructionCount\": number, \"resolveSymbols\": boolean}",
        .response_format = "{\"instructions\": [{\"address\": string, \"instruction\": string, \"symbol\": string}]}",
        .events = NULL,
        .has_options = true,
        .option_types = "memory_reference|offset|instruction_offset|count|resolve_symbols",
        .option_descriptions = "Memory reference and optional parameters",
        .examples = "disassemble 0x1000|Disassemble at address 0x1000|disassemble main -c 10|Disassemble 10 instructions at main|disassemble 0x1000 -s|Disassemble with symbol resolution",
        .category = CATEGORY_DISASSEMBLY,
        .implemented = true,
        .handler = handle_disassemble_command
    },
    { NULL } // Terminator
}; 
