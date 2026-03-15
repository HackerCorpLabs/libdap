#include "ui_main.h"
#include <imgui.h>
#include <cstdio>

void PanelServerInfo::render(DebuggerClient& client)
{
    if (!ImGui::Begin("Server Info")) {
        ImGui::End();
        return;
    }

    // Connection state
    ImVec4 state_color;
    switch (client.state()) {
    case ClientState::Disconnected: state_color = ImVec4(0.6f, 0.6f, 0.6f, 1.0f); break;
    case ClientState::Connected:
    case ClientState::Initialized:  state_color = ImVec4(0.2f, 0.8f, 0.2f, 1.0f); break;
    case ClientState::Running:      state_color = ImVec4(0.2f, 0.6f, 1.0f, 1.0f); break;
    case ClientState::Stopped:      state_color = ImVec4(1.0f, 0.8f, 0.2f, 1.0f); break;
    case ClientState::Terminated:   state_color = ImVec4(1.0f, 0.3f, 0.3f, 1.0f); break;
    }
    ImGui::TextColored(state_color, "State: %s", client.state_string());

    // Process info
    if (ImGui::CollapsingHeader("Process", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (client.process_name().empty()) {
            ImGui::TextDisabled("No process info");
        } else {
            ImGui::Text("Name: %s", client.process_name().c_str());
            ImGui::Text("PID:  %d", client.process_id());
        }

        if (client.state() == ClientState::Stopped) {
            ImGui::Text("Stop reason: %s", client.stop_reason().c_str());
            if (!client.hit_breakpoint_ids().empty()) {
                ImGui::Text("Hit breakpoints:");
                ImGui::SameLine();
                for (size_t i = 0; i < client.hit_breakpoint_ids().size(); i++) {
                    if (i > 0) ImGui::SameLine();
                    ImGui::Text("%d", client.hit_breakpoint_ids()[i]);
                }
            }
        }

        ImGui::Text("Current thread: %d", client.thread_id());
        ImGui::Text("Threads: %zu", client.threads().size());
    }

    // Current location
    if (ImGui::CollapsingHeader("Current Location", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (client.stack_frames().empty()) {
            ImGui::TextDisabled("No stack frames");
        } else {
            const auto& top = client.stack_frames()[0];
            ImGui::Text("Function: %s", top.name.empty() ? "<unknown>" : top.name.c_str());
            ImGui::Text("IP: 0x%04X", top.instruction_pointer);
            if (!top.source_name.empty()) {
                ImGui::Text("Source: %s:%d", top.source_name.c_str(), top.line);
            }
            if (!top.source_path.empty()) {
                ImGui::TextDisabled("Path: %s", top.source_path.c_str());
            }
            ImGui::Text("Stack depth: %zu", client.stack_frames().size());
            ImGui::Text("Variables: %zu", client.variables().size());
            ImGui::Text("Scopes: %zu", client.scopes().size());
        }
    }

    // Server capabilities
    if (ImGui::CollapsingHeader("Server Capabilities")) {
        const auto& caps = client.server_capabilities();
        if (caps.empty()) {
            ImGui::TextDisabled("No capabilities received (initialize first)");
        } else {
            if (ImGui::BeginTable("##caps", 2,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Capability", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Supported", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                ImGui::TableHeadersRow();

                for (const auto& cap : caps) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(cap.name.c_str());
                    ImGui::TableNextColumn();
                    if (cap.supported)
                        ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "Yes");
                    else
                        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "No");
                }
                ImGui::EndTable();
            }
        }
    }

    // Session stats
    if (ImGui::CollapsingHeader("Session")) {
        ImGui::Text("Breakpoints: %zu source, %zu instruction, %zu data",
                     client.breakpoints().size(),
                     client.instruction_breakpoints().size(),
                     client.data_breakpoints().size());
        ImGui::Text("Modules: %zu", client.modules().size());
        ImGui::Text("Symbols: %zu", client.symbols().size());
        ImGui::Text("Console log: %zu entries", client.console_log().size());
        ImGui::Text("Protocol log: %zu entries", client.protocol_log().size());
        ImGui::Text("Terminal capture: %s",
                     client.active_terminal() >= 0 ? "active" : "inactive");
        ImGui::Text("Auto-disassemble: %s", client.auto_disassemble() ? "on" : "off");
    }

    ImGui::End();
}
