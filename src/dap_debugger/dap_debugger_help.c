#include "dap_debugger_help.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const CommandHelpInfo command_help[] = {
    {
        "help",
        "help [command]",
        "Show help information. If a command is specified, show detailed help for that command.",
        "N/A - This is a client-side command",
        "N/A - This is a client-side command",
        "N/A",
        "help\nhelp initialize"
    },
    {
        "initialize",
        "initialize",
        "Initialize the debug adapter. The client sends this request once as the first command to start a debug session.",
        "Request: {\n"
        "  \"clientID\": \"string\",\n"
        "  \"clientName\": \"string\",\n"
        "  \"adapterID\": \"string\",\n"
        "  \"pathFormat\": \"path|uri\",\n"
        "  \"linesStartAt1\": boolean,\n"
        "  \"columnsStartAt1\": boolean,\n"
        "  \"supportsVariableType\": boolean,\n"
        "  \"supportsVariablePaging\": boolean,\n"
        "  ... additional capabilities ...\n"
        "}",
        "Response: {\n"
        "  \"success\": boolean,\n"
        "  \"body\": {\n"
        "    \"capabilities\": {\n"
        "      \"supportsConfigurationDoneRequest\": boolean,\n"
        "      \"supportsFunctionBreakpoints\": boolean,\n"
        "      ... server capabilities ...\n"
        "    }\n"
        "  }\n"
        "}",
        "After Initialize:\n"
        "- initialized: Sent by the debug adapter to the client after initialization",
        "initialize"
    },
    // ... (copy all other entries from dap_debugger_main.c)
    { .command_name = NULL }
};

const CommandInfo commands[] = {
    {"help", NULL, "Show this help message", CATEGORY_PROGRAM_CONTROL, true, false, NULL, NULL},
    {"initialize", NULL, "Initialize debug session", CATEGORY_PROGRAM_CONTROL, true, false, NULL, NULL},
    {"launch", NULL, "Launch program", CATEGORY_PROGRAM_CONTROL, true, true, "file,stop_at_entry", "Program file path,Stop at entry point"},
    {"attach", NULL, "Attach to process", CATEGORY_PROGRAM_CONTROL, false, true, "pid,host,port", "Process ID,Host name,Port number"},
    {"disconnect", NULL, "Disconnect from debugger", CATEGORY_PROGRAM_CONTROL, true, true, "restart,terminate", "Restart debuggee,Terminate debuggee"},
    {"terminate", NULL, "Terminate program", CATEGORY_PROGRAM_CONTROL, true, true, "restart", "Restart debuggee"},
    {"restart", NULL, "Restart program", CATEGORY_PROGRAM_CONTROL, true, false, NULL, NULL},
    {"configuration-done", NULL, "Signal end of configuration", CATEGORY_PROGRAM_CONTROL, true, false, NULL, NULL},
    {"continue", "c", "Continue execution", CATEGORY_EXECUTION_CONTROL, true, true, "thread", "Thread ID to continue"},
    {"next", "n", "Step over", CATEGORY_EXECUTION_CONTROL, true, true, "thread,granularity", "Thread ID,Step granularity"},
    {"step-in", "s", "Step into", CATEGORY_EXECUTION_CONTROL, true, true, "thread,target,granularity", "Thread ID,Target ID,Step granularity"},
    {"step-out", "o", "Step out", CATEGORY_EXECUTION_CONTROL, true, true, "thread,granularity", "Thread ID,Step granularity"},
    {"pause", NULL, "Pause execution", CATEGORY_EXECUTION_CONTROL, true, true, "thread", "Thread ID to pause"},
    {"break", "b", "Set or list breakpoints", CATEGORY_BREAKPOINTS, true, true, "line,file,condition", "Line number,File path,Condition expression"},
    {"clear", NULL, "Clear breakpoint at line", CATEGORY_BREAKPOINTS, true, true, "line,file", "Line number,File path"},
    {"clear-all", NULL, "Clear all breakpoints", CATEGORY_BREAKPOINTS, true, true, "file", "File path"},
    {"set-function-breakpoints", NULL, "Set function breakpoints", CATEGORY_BREAKPOINTS, false, true, "names", "Function names"},
    {"set-exception-breakpoints", NULL, "Set exception breakpoints", CATEGORY_BREAKPOINTS, false, true, "filters", "Exception filters"},
    {"stack", NULL, "Show stack trace", CATEGORY_STACK_AND_VARIABLES, true, true, "thread,start,levels", "Thread ID,Start frame,Number of levels"},
    {"scopes", NULL, "Show scopes", CATEGORY_STACK_AND_VARIABLES, true, true, "frame", "Frame ID"},
    {"variables", NULL, "Show variables in current scope", CATEGORY_STACK_AND_VARIABLES, true, true, "reference,start,count", "Variables reference,Start index,Count"},
    {"set-variable", NULL, "Set variable value", CATEGORY_STACK_AND_VARIABLES, true, true, "reference,name,value", "Variables reference,Variable name,New value"},
    {"source", NULL, "Show source code", CATEGORY_SOURCE, true, true, "path,reference", "Source path,Source reference"},
    {"loaded-sources", NULL, "List loaded sources", CATEGORY_SOURCE, true, false, NULL, NULL},
    {"threads", NULL, "List threads", CATEGORY_THREADS, true, false, NULL, NULL},
    {"evaluate", NULL, "Evaluate expression", CATEGORY_EVALUATION, true, true, "expression,frame,context", "Expression to evaluate,Frame ID,Evaluation context"},
    {"set-expression", NULL, "Set expression value", CATEGORY_EVALUATION, true, true, "expression,value,frame", "Expression to set,New value,Frame ID"},
    {"read-memory", NULL, "Read memory at address", CATEGORY_MEMORY, true, true, "reference,offset,count", "Memory reference,Offset,Byte count"},
    {"write-memory", NULL, "Write memory at address", CATEGORY_MEMORY, true, true, "reference,offset,data", "Memory reference,Offset,Data to write"},
    {"disassemble", NULL, "Disassemble code at address", CATEGORY_DISASSEMBLY, true, true, "reference,offset,count", "Memory reference,Offset,Instruction count"},
    {"read-registers", NULL, "Read register values", CATEGORY_REGISTERS, true, false, NULL, NULL},
    {"write-registers", NULL, "Write register values", CATEGORY_REGISTERS, true, true, "registers", "Register values"},
    {"quit", "q", "Exit debugger", CATEGORY_OTHER, true, false, NULL, NULL},
    {NULL, NULL, NULL, CATEGORY_OTHER, false, false, NULL, NULL}
};

char* str_repeat(char c, int count) {
    static char buffer[256];
    memset(buffer, c, count);
    buffer[count] = '\0';
    return buffer;
}

const char* category_to_text(CommandCategory category) {
    switch (category) {
        case CATEGORY_PROGRAM_CONTROL: return "Program Control";
        case CATEGORY_EXECUTION_CONTROL: return "Execution Control";
        case CATEGORY_BREAKPOINTS: return "Breakpoints";
        case CATEGORY_STACK_AND_VARIABLES: return "Stack and Variables";
        case CATEGORY_SOURCE: return "Source";
        case CATEGORY_THREADS: return "Threads";
        case CATEGORY_EVALUATION: return "Evaluation";
        case CATEGORY_MEMORY: return "Memory";
        case CATEGORY_DISASSEMBLY: return "Disassembly";
        case CATEGORY_REGISTERS: return "Registers";
        case CATEGORY_OTHER: return "Other";
        default: return "Unknown";
    }
}

void print_shell_help(void) {
    printf("\nDebugger Commands:\n");
    printf("=================\n\n");
    for (CommandCategory category = 0; category < CATEGORY_COUNT; category++) {
        bool has_commands = false;
        for (int i = 0; commands[i].name; i++) {
            if (commands[i].category == category) {
                has_commands = true;
                break;
            }
        }
        if (!has_commands) continue;
        const char* category_name = category_to_text(category);
        printf("%s:\n", category_name);
        printf("%s\n", str_repeat('-', strlen(category_name) + 1));
        for (int i = 0; commands[i].name; i++) {
            if (commands[i].category == category) {
                printf("  %-25s %-5s %s %s\n",
                       commands[i].name,
                       commands[i].alias ? commands[i].alias : "",
                       commands[i].implemented ? "✓" : " ",
                       commands[i].description);
                if (commands[i].has_options && commands[i].option_types) {
                    printf("    Options:\n");
                    char* types = strdup(commands[i].option_types);
                    char* descs = strdup(commands[i].option_descriptions);
                    char* type = strtok(types, ",");
                    char* desc = strtok(descs, ",");
                    while (type && desc) {
                        printf("      %-15s %s\n", type, desc);
                        type = strtok(NULL, ",");
                        desc = strtok(NULL, ",");
                    }
                    free(types);
                    free(descs);
                }
            }
        }
        printf("\n");
    }
    printf("Debugger status: (see main)\n");
    printf("Note: Commands marked with ✓ are implemented\n");
} 