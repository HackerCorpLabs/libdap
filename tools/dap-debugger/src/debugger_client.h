#ifndef DEBUGGER_CLIENT_H
#define DEBUGGER_CLIENT_H

#include <string>
#include <vector>
#include <cstdint>

enum class ClientState {
    Disconnected,
    Connected,
    Initialized,
    Running,
    Stopped,
    Terminated
};

struct ConsoleEntry {
    enum Category { Info, Warning, Error, DapEvent, DapResponse, UserInput };
    Category category;
    std::string text;
};

struct ProtocolEntry {
    enum Direction { Sent, Received };
    Direction direction;
    std::string json;
};

struct StackFrameInfo {
    int id;
    std::string name;
    std::string source_path;
    std::string source_name;
    int line;
    int instruction_pointer;
};

struct VariableInfo {
    std::string name;
    std::string value;
    std::string type;
    int variables_reference;
};

struct BreakpointInfo {
    int id;
    bool verified;
    std::string source_path;
    int line;
    uint32_t instruction_reference;
    std::string condition;
    std::string hit_condition;
    std::string log_message;
    std::string message;
};

struct DataBreakpointInfo {
    int id;
    bool verified;
    std::string data_id;
    int access_type;  // 0=read, 1=write, 2=readwrite
    uint32_t address;
    std::string condition;
    std::string message;
};

struct InstructionBreakpointInfo {
    uint32_t instruction_reference;
    int offset;
    std::string condition;
    std::string hit_condition;
    // Result fields
    int id;
    bool verified;
    std::string message;
};

struct DisassemblyLine {
    std::string address;
    std::string instruction;
    std::string instruction_bytes;
    std::string symbol;
    std::string source_path;
    int line;
};

struct ModuleInfo {
    std::string id;
    std::string name;
    std::string path;
    std::string version;
    std::string symbol_status;
    std::string address_range;
    bool is_optimized;
    bool is_user_code;
};

struct ThreadInfo {
    int id;
    std::string name;
};

struct SymbolInfo {
    std::string name;
    uint32_t address;
    std::string type;       // "function", "label", "variable"
    std::string source_path;
    int line;
};

struct ServerCapability {
    std::string name;
    bool supported;
};

struct ScopeInfo {
    std::string name;
    int variables_reference;
    std::vector<VariableInfo> variables;
};

class DebuggerClient {
public:
    DebuggerClient();
    ~DebuggerClient();

    // Connection
    void connect(const std::string& host, int port);
    void initialize();
    struct LaunchArgs {
        std::string program;
        std::string source_file;
        std::string map_file;
        std::string cwd;
        bool stop_on_entry = true;
    };
    void launch(const std::string& program);
    void launch(const LaunchArgs& args);
    void disconnect();
    void force_close();  // Close socket immediately without sending disconnect request

    // Execution control
    void do_continue();
    void step_over();
    void step_in();
    void step_out();
    void step_back();
    void pause();

    // Data queries (called automatically on stop)
    void refresh_stack_trace();
    void refresh_variables(int frame_id);
    void refresh_scopes(int frame_id);

    // Source breakpoints
    void add_source_breakpoint(const std::string& source, int line,
                               const std::string& condition = "",
                               const std::string& hit_condition = "",
                               const std::string& log_message = "");
    void remove_source_breakpoint(int id);
    void clear_breakpoints(const std::string& source);

    // Instruction breakpoints
    void set_instruction_breakpoints(const std::vector<InstructionBreakpointInfo>& bps);
    const std::vector<InstructionBreakpointInfo>& instruction_breakpoints() const { return instruction_breakpoints_; }

    // Data breakpoints (watchpoints)
    void add_data_breakpoint(const std::string& data_id, int access_type,
                             const std::string& condition = "");
    void remove_data_breakpoint(int id);
    void clear_data_breakpoints();
    const std::vector<DataBreakpointInfo>& data_breakpoints() const { return data_breakpoints_; }

    // Disassembly
    void disassemble(uint32_t address, int count, bool resolve_symbols = true);
    void disassemble_extend(uint32_t address, int count, bool resolve_symbols = true);
    const std::vector<DisassemblyLine>& disassembly() const { return disassembly_; }
    uint32_t disasm_cache_start() const { return disasm_cache_start_; }
    uint32_t disasm_cache_end() const { return disasm_cache_end_; }

    // Memory
    std::string read_memory(uint32_t address, uint32_t offset, size_t count);
    bool write_memory(uint32_t address, uint32_t offset, const std::string& data);

    // Threads
    void refresh_threads();
    const std::vector<ThreadInfo>& threads() const { return threads_; }

    // Modules
    void refresh_modules();
    const std::vector<ModuleInfo>& modules() const { return modules_; }

    // Evaluate
    void evaluate(const std::string& expression, int frame_id = 0);

    // Set variable
    void set_variable(int variables_reference, const std::string& name, const std::string& value);

    // Symbol list (custom DAP extension)
    void fetch_symbols();
    const std::vector<SymbolInfo>& symbols() const { return symbols_; }

    // Server capabilities
    const std::vector<ServerCapability>& server_capabilities() const { return server_capabilities_; }

    // Terminal console I/O
    void console_enable(int terminal, bool enable);
    void console_write(int terminal, const std::string& input);
    const std::vector<std::string>& terminal_output() const { return terminal_output_; }
    void clear_terminal_output() { terminal_output_.clear(); }
    int active_terminal() const { return active_terminal_; }

    // Polling
    void poll();

    // Accessors
    ClientState state() const { return state_; }
    const char* state_string() const;
    int thread_id() const { return thread_id_; }

    const std::vector<StackFrameInfo>& stack_frames() const { return stack_frames_; }
    const std::vector<ScopeInfo>& scopes() const { return scopes_; }
    const std::vector<VariableInfo>& variables() const { return variables_; }
    const std::vector<BreakpointInfo>& breakpoints() const { return breakpoints_; }
    const std::vector<ConsoleEntry>& console_log() const { return console_log_; }
    const std::vector<ProtocolEntry>& protocol_log() const { return protocol_log_; }
    void clear_protocol_log() { protocol_log_.clear(); }

    void set_debug(bool on) { debug_ = on; }
    bool debug() const { return debug_; }

    void log(ConsoleEntry::Category cat, const std::string& text);
    void log_protocol(ProtocolEntry::Direction dir, const std::string& json);

    // Process info
    const std::string& process_name() const { return process_name_; }
    int process_id() const { return process_id_; }
    const std::string& stop_reason() const { return stop_reason_; }
    const std::vector<int>& hit_breakpoint_ids() const { return hit_breakpoint_ids_; }

    // Auto-disassemble on stop
    void set_auto_disassemble(bool on) { auto_disassemble_ = on; }
    bool auto_disassemble() const { return auto_disassemble_; }
    void set_disassemble_count(int n) { disassemble_count_ = n; }

private:
    void log_protocol_sent(const char* command, void* args_json);
    void log_protocol_received(void* message_json);
    void handle_event(const char* event_name, void* body_json);
    void handle_stopped_event(void* body_json);
    void handle_continued_event(void* body_json);
    void handle_output_event(void* body_json);
    void handle_thread_event(void* body_json);
    void handle_breakpoint_event(void* body_json);
    void handle_process_event(void* body_json);
    void handle_module_event(void* body_json);
    void handle_memory_event(void* body_json);
    void handle_capabilities_event(void* body_json);
    void on_stopped();
    void sync_source_breakpoints(const std::string& source);

    struct Impl;
    Impl* impl_;

    ClientState state_ = ClientState::Disconnected;
    int thread_id_ = 1;
    bool debug_ = false;
    bool auto_disassemble_ = true;
    int disassemble_count_ = 20;
    bool needs_refresh_ = false;

    // Disassembly cache range tracking
    uint32_t disasm_cache_start_ = 0;  // First address in cached disassembly
    uint32_t disasm_cache_end_ = 0;    // Last address in cached disassembly

    // Process state
    std::string process_name_;
    int process_id_ = 0;
    std::string stop_reason_;
    std::vector<int> hit_breakpoint_ids_;

    std::vector<StackFrameInfo> stack_frames_;
    std::vector<ScopeInfo> scopes_;
    std::vector<VariableInfo> variables_;
    std::vector<BreakpointInfo> breakpoints_;
    std::vector<InstructionBreakpointInfo> instruction_breakpoints_;
    std::vector<DataBreakpointInfo> data_breakpoints_;
    std::vector<DisassemblyLine> disassembly_;
    std::vector<ThreadInfo> threads_;
    std::vector<SymbolInfo> symbols_;
    std::vector<ServerCapability> server_capabilities_;
    std::vector<ModuleInfo> modules_;
    std::vector<ConsoleEntry> console_log_;
    std::vector<ProtocolEntry> protocol_log_;
    std::vector<std::string> terminal_output_;
    int active_terminal_ = -1;
    std::string current_source_;
};

#endif // DEBUGGER_CLIENT_H
