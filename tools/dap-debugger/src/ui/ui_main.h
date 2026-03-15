#ifndef UI_MAIN_H
#define UI_MAIN_H

#include "../debugger_client.h"
#include "../app.h"

class PanelConsole;
class PanelStack;
class PanelRegisters;
class PanelSource;
class PanelBreakpoints;
class PanelTerminal;
class PanelThreads;
class PanelProtocol;
class PanelSymbols;
class PanelServerInfo;

class UIMain {
public:
    UIMain();
    ~UIMain();

    void setup_docking();
    void render(DebuggerClient& client, const AppConfig& config);

private:
    void render_menu_bar(DebuggerClient& client, const AppConfig& config);
    void render_toolbar(DebuggerClient& client);
    void render_status_bar(DebuggerClient& client);

    PanelConsole* panel_console_;
    PanelStack* panel_stack_;
    PanelRegisters* panel_registers_;
    PanelSource* panel_source_;
    PanelBreakpoints* panel_breakpoints_;
    PanelTerminal* panel_terminal_;
    PanelThreads* panel_threads_;
    PanelProtocol* panel_protocol_;
    PanelSymbols* panel_symbols_;
    PanelServerInfo* panel_server_info_;

    void handle_keyboard_shortcuts(DebuggerClient& client, const AppConfig& config);

    bool show_connect_dialog_ = false;
    bool show_launch_dialog_ = false;
    char connect_host_[256] = "localhost";
    int connect_port_ = 5555;
    char launch_program_[512] = {};
    char launch_source_[512] = {};
    char launch_map_[512] = {};
    char launch_cwd_[512] = {};
    bool launch_stop_on_entry_ = true;
};

// Panel classes
class PanelConsole {
public:
    void render(DebuggerClient& client);
private:
    char input_buf_[512] = {};
    bool auto_scroll_ = true;
    bool scroll_to_bottom_ = false;
    size_t last_count_ = 0;
    std::string text_buf_;
};

class PanelStack {
public:
    void render(DebuggerClient& client);
private:
    int selected_ = 0;
};

class PanelRegisters {
public:
    void render(DebuggerClient& client);
};

class PanelSource {
public:
    void render(DebuggerClient& client);
private:
    std::string loaded_source_path_;
    std::vector<std::string> source_lines_;
    void load_source_file(const std::string& path);
};

class PanelBreakpoints {
public:
    void render(DebuggerClient& client);
private:
    char source_buf_[256] = {};
    int line_buf_ = 1;
};

class PanelThreads {
public:
    void render(DebuggerClient& client);
};

class PanelSymbols {
public:
    struct SymbolEntry {
        std::string name;
        uint32_t address;
        std::string source_path;
        int line;
    };
    void render(DebuggerClient& client);
private:
    std::vector<SymbolEntry> scan_symbols_;
    char filter_buf_[128] = {};
    int symbol_type_ = 0;
    uint32_t scan_start_ = 0;
    uint32_t scan_end_ = 0x1000;
    bool use_dap_symbols_ = true;
};

class PanelServerInfo {
public:
    void render(DebuggerClient& client);
};

class PanelProtocol {
public:
    void render(DebuggerClient& client);
private:
    bool auto_scroll_ = true;
    bool show_sent_ = true;
    bool show_received_ = true;
    bool show_requests_ = true;
    bool show_responses_ = true;
    bool show_events_ = true;
    char search_buf_[256] = {};
    size_t last_count_ = 0;
    std::string text_buf_;
};

class PanelTerminal {
public:
    void render(DebuggerClient& client);
private:
    int terminal_id_ = 192;
    char selected_label_[64] = "Console (0300)";
    char input_buf_[512] = {};
    bool send_newline_ = true;
    bool auto_scroll_ = true;
    size_t last_output_count_ = 0;
};

#endif // UI_MAIN_H
