#include "ui_main.h"
#include <imgui.h>
#include <cstring>
#include <cstdio>

// Common ND-100 terminal IOX base addresses (decimal)
static const struct { int address; const char* name; } known_terminals[] = {
    { 192, "Console (0300)" },
    { 200, "Terminal 1 (0310)" },
    { 208, "Terminal 2 (0320)" },
    { 216, "Terminal 3 (0330)" },
    { 224, "Terminal 4 (0340)" },
    { 232, "Terminal 5 (0350)" },
    { 240, "Terminal 6 (0360)" },
    { 248, "Terminal 7 (0370)" },
};
static const int num_known_terminals = sizeof(known_terminals) / sizeof(known_terminals[0]);

void PanelTerminal::render(DebuggerClient& client)
{
    if (!ImGui::Begin("Terminal I/O")) {
        ImGui::End();
        return;
    }

    if (client.state() == ClientState::Disconnected) {
        ImGui::TextDisabled("Not connected");
        ImGui::End();
        return;
    }

    // Terminal selection and enable/disable
    ImGui::Text("Terminal:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200.0f);
    if (ImGui::BeginCombo("##terminal_select", selected_label_)) {
        for (int i = 0; i < num_known_terminals; i++) {
            bool is_selected = (terminal_id_ == known_terminals[i].address);
            if (ImGui::Selectable(known_terminals[i].name, is_selected)) {
                terminal_id_ = known_terminals[i].address;
                snprintf(selected_label_, sizeof(selected_label_), "%s", known_terminals[i].name);
            }
            if (is_selected) ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.0f);
    ImGui::InputInt("##custom_id", &terminal_id_, 0);
    ImGui::SameLine();

    bool capturing = client.active_terminal() == terminal_id_;
    if (!capturing) {
        if (ImGui::Button("Enable Capture")) {
            // Disable any previous capture first
            if (client.active_terminal() >= 0) {
                client.console_enable(client.active_terminal(), false);
            }
            client.console_enable(terminal_id_, true);
        }
    } else {
        if (ImGui::Button("Disable Capture")) {
            client.console_enable(terminal_id_, false);
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        client.clear_terminal_output();
    }

    // Status indicator
    if (client.active_terminal() >= 0) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), " [Capturing terminal %d]",
                           client.active_terminal());
    }

    ImGui::Separator();

    // Terminal output display
    float footer_height = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();
    if (ImGui::BeginChild("##TermOutput", ImVec2(0, -footer_height), ImGuiChildFlags_None,
                          ImGuiWindowFlags_HorizontalScrollbar)) {

        // Use monospace-style rendering for terminal feel
        const auto& output = client.terminal_output();

        // Build display text from output fragments
        // Each entry may be a single char or a short string
        for (const auto& fragment : output) {
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "%s", fragment.c_str());
        }

        // Auto-scroll
        if (output.size() != last_output_count_) {
            if (auto_scroll_) {
                ImGui::SetScrollHereY(1.0f);
            }
            last_output_count_ = output.size();
        }
    }
    ImGui::EndChild();

    // Keyboard input line
    ImGui::Separator();
    bool active_capture = client.active_terminal() >= 0;

    ImGui::BeginDisabled(!active_capture);
    ImGui::SetNextItemWidth(-120.0f);
    ImGuiInputTextFlags input_flags = ImGuiInputTextFlags_EnterReturnsTrue;
    bool send = ImGui::InputText("##term_input", input_buf_, sizeof(input_buf_), input_flags);
    ImGui::SameLine();
    send |= ImGui::Button("Send");
    ImGui::SameLine();
    if (ImGui::Button("CR")) {
        // Send carriage return
        client.console_write(client.active_terminal(), "\r");
    }
    ImGui::EndDisabled();

    if (send && active_capture && strlen(input_buf_) > 0) {
        std::string text = input_buf_;
        if (send_newline_) {
            text += "\r";
        }
        client.console_write(client.active_terminal(), text);
        input_buf_[0] = '\0';
        ImGui::SetKeyboardFocusHere(-2);
    }

    // Options
    ImGui::Checkbox("Append CR on send", &send_newline_);
    ImGui::SameLine();
    ImGui::Checkbox("Auto-scroll", &auto_scroll_);

    ImGui::End();
}
