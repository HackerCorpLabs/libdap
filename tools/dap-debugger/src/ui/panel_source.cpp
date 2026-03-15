#include "ui_main.h"
#include <imgui.h>
#include <cstdio>

void PanelSource::render(DebuggerClient& client)
{
    if (!ImGui::Begin("Source")) {
        ImGui::End();
        return;
    }

    if (client.state() == ClientState::Disconnected) {
        ImGui::TextDisabled("Not connected");
        ImGui::End();
        return;
    }

    const auto& frames = client.stack_frames();

    if (ImGui::BeginTabBar("##source_tabs")) {
        // --- Location Tab ---
        if (ImGui::BeginTabItem("Location")) {
            if (frames.empty()) {
                ImGui::TextDisabled("No stack frames available");
            } else {
                const auto& top = frames[0];

                ImGui::Text("Function: %s", top.name.empty() ? "<unknown>" : top.name.c_str());
                ImGui::SameLine(0, 20);
                ImGui::Text("IP: 0x%04X", top.instruction_pointer);

                if (!top.source_name.empty()) {
                    ImGui::Text("Source: %s", top.source_name.c_str());
                    if (top.line > 0) {
                        ImGui::SameLine();
                        ImGui::Text("  Line: %d", top.line);
                    }
                }

                if (!top.source_path.empty()) {
                    ImGui::TextDisabled("Path: %s", top.source_path.c_str());
                }

                ImGui::Separator();
                ImGui::TextColored(ImVec4(0.7f, 0.9f, 1.0f, 1.0f), "Call Location Trail:");
                for (size_t i = 0; i < frames.size(); i++) {
                    const auto& f = frames[i];
                    ImVec4 color = (i == 0) ? ImVec4(1.0f, 1.0f, 0.4f, 1.0f) : ImVec4(0.7f, 0.7f, 0.7f, 1.0f);
                    if (f.line > 0 && !f.source_name.empty()) {
                        ImGui::TextColored(color, "  #%zu  0x%04X  %s  %s:%d",
                            i, f.instruction_pointer, f.name.c_str(),
                            f.source_name.c_str(), f.line);
                    } else {
                        ImGui::TextColored(color, "  #%zu  0x%04X  %s",
                            i, f.instruction_pointer, f.name.c_str());
                    }
                }
            }
            ImGui::EndTabItem();
        }

        // --- Disassembly Tab ---
        if (ImGui::BeginTabItem("Disassembly")) {
            static uint32_t disasm_addr = 0;
            static int disasm_count = 20;

            // Default to current IP
            if (disasm_addr == 0 && !frames.empty()) {
                disasm_addr = (uint32_t)frames[0].instruction_pointer;
            }

            ImGui::SetNextItemWidth(120.0f);
            ImGui::InputScalar("Address", ImGuiDataType_U32, &disasm_addr, nullptr, nullptr, "0x%04X",
                               ImGuiInputTextFlags_CharsHexadecimal);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(80.0f);
            ImGui::InputInt("Count", &disasm_count);
            if (disasm_count < 1) disasm_count = 1;
            if (disasm_count > 200) disasm_count = 200;
            ImGui::SameLine();
            bool stopped = client.state() == ClientState::Stopped;
            ImGui::BeginDisabled(!stopped);
            if (ImGui::Button("Disassemble")) {
                client.disassemble(disasm_addr, disasm_count);
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            if (!frames.empty()) {
                if (ImGui::Button("Go to IP")) {
                    disasm_addr = (uint32_t)frames[0].instruction_pointer;
                    if (stopped) {
                        client.disassemble(disasm_addr, disasm_count);
                    }
                }
            }

            ImGui::Separator();

            const auto& disasm = client.disassembly();
            if (disasm.empty()) {
                ImGui::TextDisabled("No disassembly (press Disassemble)");
            } else {
                if (ImGui::BeginTable("##disasm", 4,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
                    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                    ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                    ImGui::TableHeadersRow();

                    uint32_t current_ip = frames.empty() ? 0 : (uint32_t)frames[0].instruction_pointer;

                    for (const auto& dl : disasm) {
                        ImGui::TableNextRow();

                        // Highlight current IP
                        uint32_t line_addr = (uint32_t)strtoul(dl.address.c_str(), nullptr, 0);
                        bool is_current = (line_addr == current_ip && current_ip != 0);
                        ImVec4 text_color = is_current ? ImVec4(1.0f, 1.0f, 0.2f, 1.0f)
                                                       : ImVec4(0.8f, 0.8f, 0.8f, 1.0f);

                        ImGui::TableNextColumn();
                        ImGui::TextColored(text_color, "%s%s", is_current ? ">" : " ", dl.address.c_str());
                        ImGui::TableNextColumn();
                        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "%s", dl.instruction_bytes.c_str());
                        ImGui::TableNextColumn();
                        ImGui::TextColored(text_color, "%s", dl.instruction.c_str());
                        ImGui::TableNextColumn();
                        if (!dl.symbol.empty()) {
                            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "%s", dl.symbol.c_str());
                        }
                    }
                    ImGui::EndTable();
                }
            }
            ImGui::EndTabItem();
        }

        // --- Memory Tab ---
        if (ImGui::BeginTabItem("Memory")) {
            static uint32_t mem_addr = 0;
            static int mem_count = 64;

            ImGui::SetNextItemWidth(120.0f);
            ImGui::InputScalar("Address##mem", ImGuiDataType_U32, &mem_addr, nullptr, nullptr, "0x%04X",
                               ImGuiInputTextFlags_CharsHexadecimal);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(80.0f);
            ImGui::InputInt("Bytes", &mem_count);
            if (mem_count < 1) mem_count = 1;
            if (mem_count > 1024) mem_count = 1024;
            ImGui::SameLine();
            bool stopped_m = client.state() == ClientState::Stopped;
            ImGui::BeginDisabled(!stopped_m);
            static std::string mem_data;
            if (ImGui::Button("Read")) {
                mem_data = client.read_memory(mem_addr, 0, (size_t)mem_count);
            }
            ImGui::EndDisabled();

            ImGui::Separator();
            if (mem_data.empty()) {
                ImGui::TextDisabled("No memory data (press Read)");
            } else {
                ImGui::TextWrapped("Data (base64): %s", mem_data.c_str());
            }
            ImGui::EndTabItem();
        }

        // --- Modules Tab ---
        if (ImGui::BeginTabItem("Modules")) {
            bool stopped_mod = client.state() == ClientState::Stopped;
            ImGui::BeginDisabled(!stopped_mod);
            if (ImGui::Button("Refresh Modules")) {
                client.refresh_modules();
            }
            ImGui::EndDisabled();

            ImGui::Separator();
            const auto& mods = client.modules();
            if (mods.empty()) {
                ImGui::TextDisabled("No modules loaded");
            } else {
                if (ImGui::BeginTable("##modules", 5,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
                    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Version", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                    ImGui::TableSetupColumn("Symbols", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                    ImGui::TableSetupColumn("Range", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                    ImGui::TableHeadersRow();

                    for (const auto& m : mods) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(m.name.c_str());
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(m.path.c_str());
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(m.version.c_str());
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(m.symbol_status.c_str());
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(m.address_range.c_str());
                    }
                    ImGui::EndTable();
                }
            }
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::End();
}
